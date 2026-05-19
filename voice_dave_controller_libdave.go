//go:build libdave && cgo
// +build libdave,cgo

package discordgo

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/bwmarrin/discordgo/dave"
)

type voiceDAVESpeakingObserver interface {
	HandleSpeakingUpdate(vc *VoiceConnection, vs *VoiceSpeakingUpdate)
}

type libdaveVoiceController struct {
	mu sync.Mutex

	session         *dave.Session
	encryptor       *dave.Encryptor
	protocolVersion uint16
	localUserID     string

	ratchets   map[string]*dave.KeyRatchet
	decryptors map[uint32]*dave.Decryptor
	ssrcUsers  map[uint32]string
	knownUsers map[string]struct{}

	outboundRatchetSet bool
	outboundSSRC       uint32
}

func newDefaultDAVEController(vc *VoiceConnection) VoiceDAVEController {
	c := &libdaveVoiceController{
		ratchets:   make(map[string]*dave.KeyRatchet),
		decryptors: make(map[uint32]*dave.Decryptor),
		ssrcUsers:  make(map[uint32]string),
		knownUsers: make(map[string]struct{}),
	}
	if vc != nil && vc.UserID != "" {
		c.knownUsers[vc.UserID] = struct{}{}
		c.localUserID = vc.UserID
	}
	return c
}

func closeDAVEController(c VoiceDAVEController) {
	if closer, ok := c.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func (c *libdaveVoiceController) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for ssrc, dec := range c.decryptors {
		if dec != nil {
			dec.Close()
		}
		delete(c.decryptors, ssrc)
	}
	for userID, kr := range c.ratchets {
		if kr != nil {
			kr.Close()
		}
		delete(c.ratchets, userID)
	}
	if c.session != nil {
		c.session.Destroy()
		c.session = nil
	}
	if c.encryptor != nil {
		c.encryptor.Close()
		c.encryptor = nil
	}
	return nil
}

func (c *libdaveVoiceController) PrepareTransition(vc *VoiceConnection, transitionID, protocolVersion int) (ready bool, err error) {
	if err = c.ensureSession(vc, uint16(protocolVersion)); err != nil {
		return false, err
	}

	c.mu.Lock()
	c.protocolVersion = uint16(protocolVersion)
	enc := c.encryptor
	for _, dec := range c.decryptors {
		if dec == nil {
			continue
		}
		dec.TransitionToPassthroughMode(protocolVersion == 0)
	}
	c.mu.Unlock()
	if enc != nil {
		enc.SetPassthroughMode(protocolVersion == 0)
	}

	return true, nil
}

func (c *libdaveVoiceController) PrepareEpoch(vc *VoiceConnection, transitionID, protocolVersion int, epoch uint64) (ready bool, keyPackage []byte, err error) {
	if err = c.ensureSession(vc, uint16(protocolVersion)); err != nil {
		return false, nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if epoch <= 1 {
		if c.session == nil {
			return false, nil, nil
		}
		return false, c.session.MarshalledKeyPackage(), nil
	}

	return true, nil, nil
}

func (c *libdaveVoiceController) ExecuteTransition(vc *VoiceConnection, transitionID int) error {
	return nil
}

func (c *libdaveVoiceController) ClientsConnected(vc *VoiceConnection, userIDs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, userID := range userIDs {
		if userID != "" {
			c.knownUsers[userID] = struct{}{}
		}
	}
}

func (c *libdaveVoiceController) ClientDisconnected(vc *VoiceConnection, userID string) {
	if userID == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.knownUsers, userID)

	if kr := c.ratchets[userID]; kr != nil {
		kr.Close()
	}
	delete(c.ratchets, userID)

	for ssrc, mappedUserID := range c.ssrcUsers {
		if mappedUserID != userID {
			continue
		}
		if dec := c.decryptors[ssrc]; dec != nil {
			dec.Close()
		}
		delete(c.decryptors, ssrc)
		delete(c.ssrcUsers, ssrc)
	}
}

func (c *libdaveVoiceController) HandleMLSExternalSender(vc *VoiceConnection, externalSender []byte) error {
	if len(externalSender) == 0 {
		return nil
	}
	if err := c.ensureSession(vc, c.currentProtocolVersion()); err != nil {
		return err
	}

	c.mu.Lock()
	if c.session != nil {
		c.session.SetExternalSender(externalSender)
		keyPackage := c.session.MarshalledKeyPackage()
		c.mu.Unlock()
		if len(keyPackage) > 0 {
			return vc.SendDAVEKeyPackage(keyPackage)
		}
		return nil
	}
	c.mu.Unlock()

	return nil
}

func (c *libdaveVoiceController) HandleMLSProposals(vc *VoiceConnection, operationType uint8, payload []byte) (commit []byte, welcome []byte, err error) {
	if len(payload) == 0 {
		return nil, nil, nil
	}
	if err = c.ensureSession(vc, c.currentProtocolVersion()); err != nil {
		return nil, nil, err
	}

	recognized := c.recognizedUserIDs(vc)

	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return nil, nil, nil
	}

	commitWelcome := session.ProcessProposals(payload, recognized)
	if len(commitWelcome) == 0 {
		return nil, nil, nil
	}

	// OP28 payload is the commit+optional welcome bytes as a single blob.
	return commitWelcome, nil, nil
}

func (c *libdaveVoiceController) HandleMLSCommitTransition(vc *VoiceConnection, transitionID int, commit []byte) (ready bool, err error) {
	if len(commit) == 0 {
		return false, nil
	}
	if err = c.ensureSession(vc, c.currentProtocolVersion()); err != nil {
		return false, err
	}

	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return false, nil
	}

	result := session.ProcessCommit(commit)
	if result == nil {
		_ = vc.SendDAVEInvalidCommitWelcome(transitionID)
		return false, fmt.Errorf("libdave returned nil commit result")
	}
	defer result.Close()

	if result.Failed() {
		_ = vc.SendDAVEInvalidCommitWelcome(transitionID)
		return false, fmt.Errorf("libdave rejected commit transition")
	}

	if !result.Ignored() {
		c.refreshRatchets(session, result.RosterMemberIDs())
	}
	c.ensureOutboundRatchet(vc)

	return true, nil
}

func (c *libdaveVoiceController) HandleMLSWelcome(vc *VoiceConnection, transitionID int, welcome []byte) (ready bool, err error) {
	if len(welcome) == 0 {
		return false, nil
	}
	if err = c.ensureSession(vc, c.currentProtocolVersion()); err != nil {
		return false, err
	}

	recognized := c.recognizedUserIDs(vc)

	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session == nil {
		return false, nil
	}

	result := session.ProcessWelcome(welcome, recognized)
	if result == nil {
		_ = vc.SendDAVEInvalidCommitWelcome(transitionID)
		return false, fmt.Errorf("libdave returned nil welcome result")
	}
	defer result.Close()

	c.refreshRatchets(session, result.RosterMemberIDs())
	c.ensureOutboundRatchet(vc)
	return true, nil
}

func (c *libdaveVoiceController) EncryptOpus(vc *VoiceConnection, packet *Packet, opus []byte) ([]byte, error) {
	if packet == nil {
		return nil, fmt.Errorf("nil packet")
	}

	c.mu.Lock()
	protocolVersion := c.protocolVersion
	session := c.session
	enc := c.encryptor
	localUserID := c.localUserID
	if localUserID == "" && vc != nil {
		localUserID = vc.UserID
	}
	kr := c.ratchets[localUserID]
	c.mu.Unlock()

	if protocolVersion == 0 {
		return opus, nil
	}

	if kr == nil && session != nil && localUserID != "" {
		kr = session.GetKeyRatchet(localUserID)
		if kr != nil {
			c.installRatchet(localUserID, kr)
		}
	}
	if kr == nil {
		return nil, fmt.Errorf("dave outbound key ratchet unavailable")
	}

	if enc == nil {
		newEnc := dave.NewEncryptor()
		newEnc.SetPassthroughMode(false)
		c.mu.Lock()
		if c.encryptor == nil {
			c.encryptor = newEnc
			enc = newEnc
		} else {
			enc = c.encryptor
		}
		c.mu.Unlock()
		if enc != newEnc {
			newEnc.Close()
		}
	}

	c.mu.Lock()
	needSetRatchet := !c.outboundRatchetSet
	if needSetRatchet {
		c.outboundRatchetSet = true
	}
	needAssignSSRC := c.outboundSSRC != packet.SSRC
	if needAssignSSRC {
		c.outboundSSRC = packet.SSRC
	}
	c.mu.Unlock()

	if needSetRatchet {
		enc.SetKeyRatchet(kr)
	}
	if needAssignSSRC {
		enc.AssignSsrcToCodec(packet.SSRC, dave.CodecOpus)
	}
	return enc.Encrypt(dave.MediaAudio, packet.SSRC, opus)
}

func (c *libdaveVoiceController) DecryptOpus(vc *VoiceConnection, packet *Packet, opus []byte) ([]byte, error) {
	if packet == nil {
		return nil, fmt.Errorf("nil packet")
	}

	c.mu.Lock()
	protocolVersion := c.protocolVersion
	dec := c.decryptors[packet.SSRC]
	userID := c.ssrcUsers[packet.SSRC]
	session := c.session
	kr := c.ratchets[userID]
	c.mu.Unlock()

	if protocolVersion == 0 {
		return opus, nil
	}

	if dec == nil && session != nil && userID != "" {
		if kr == nil {
			kr = session.GetKeyRatchet(userID)
			if kr != nil {
				c.installRatchet(userID, kr)
			}
		}
		if kr != nil {
			dec = dave.NewDecryptor()
			dec.TransitionToKeyRatchet(kr)

			c.mu.Lock()
			c.decryptors[packet.SSRC] = dec
			c.mu.Unlock()
		}
	}

	if dec == nil {
		return nil, fmt.Errorf("dave decryptor unavailable for ssrc=%d", packet.SSRC)
	}

	return dec.Decrypt(dave.MediaAudio, opus)
}

func (c *libdaveVoiceController) HandleSpeakingUpdate(vc *VoiceConnection, vs *VoiceSpeakingUpdate) {
	if vs == nil || vs.SSRC == 0 || vs.UserID == "" {
		return
	}

	ssrc := uint32(vs.SSRC)

	c.mu.Lock()
	c.ssrcUsers[ssrc] = vs.UserID
	c.knownUsers[vs.UserID] = struct{}{}
	_, hasDecryptor := c.decryptors[ssrc]
	session := c.session
	kr := c.ratchets[vs.UserID]
	c.mu.Unlock()

	if hasDecryptor || session == nil {
		return
	}

	if kr == nil {
		kr = session.GetKeyRatchet(vs.UserID)
		if kr != nil {
			c.installRatchet(vs.UserID, kr)
		}
	}
	if kr == nil {
		return
	}

	dec := dave.NewDecryptor()
	dec.TransitionToKeyRatchet(kr)

	c.mu.Lock()
	if existing := c.decryptors[ssrc]; existing == nil {
		c.decryptors[ssrc] = dec
		dec = nil
	}
	c.mu.Unlock()

	if dec != nil {
		dec.Close()
	}
}

func (c *libdaveVoiceController) currentProtocolVersion() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.protocolVersion != 0 {
		return c.protocolVersion
	}
	return 1
}

func (c *libdaveVoiceController) ensureSession(vc *VoiceConnection, protocolVersion uint16) error {
	if vc == nil {
		return fmt.Errorf("nil voice connection")
	}
	if protocolVersion == 0 {
		protocolVersion = 1
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if vc.UserID != "" {
		c.knownUsers[vc.UserID] = struct{}{}
		c.localUserID = vc.UserID
	}

	if c.session == nil {
		groupID, err := strconv.ParseUint(vc.ChannelID, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid voice channel id %q: %w", vc.ChannelID, err)
		}

		c.session = dave.NewSession("", func(source, reason string) {
			vc.log(LogError, "DAVE MLS failure in %s: %s", source, reason)
		})
		c.session.Init(protocolVersion, groupID, vc.UserID)
	}

	c.protocolVersion = protocolVersion
	c.session.SetProtocolVersion(protocolVersion)
	return nil
}

func (c *libdaveVoiceController) installRatchet(userID string, ratchet *dave.KeyRatchet) {
	if ratchet == nil || userID == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if prev := c.ratchets[userID]; prev != nil {
		prev.Close()
	}
	c.ratchets[userID] = ratchet
	if userID == c.localUserID {
		c.outboundRatchetSet = false
	}

	for ssrc, mappedUserID := range c.ssrcUsers {
		if mappedUserID != userID {
			continue
		}
		dec := c.decryptors[ssrc]
		if dec != nil {
			dec.TransitionToKeyRatchet(ratchet)
		}
	}
}

func (c *libdaveVoiceController) refreshRatchets(session *dave.Session, roster []uint64) {
	if session == nil {
		return
	}

	want := make(map[string]struct{}, len(roster)+len(c.ssrcUsers)+1)
	for _, userIDNum := range roster {
		want[strconv.FormatUint(userIDNum, 10)] = struct{}{}
	}

	c.mu.Lock()
	for _, userID := range c.ssrcUsers {
		if userID != "" {
			want[userID] = struct{}{}
		}
	}
	c.mu.Unlock()

	for userID := range want {
		ratchet := session.GetKeyRatchet(userID)
		if ratchet == nil {
			continue
		}
		c.installRatchet(userID, ratchet)
	}
}

func (c *libdaveVoiceController) ensureOutboundRatchet(vc *VoiceConnection) {
	if vc == nil || vc.UserID == "" {
		return
	}

	c.mu.Lock()
	_, ok := c.ratchets[vc.UserID]
	session := c.session
	c.mu.Unlock()
	if ok || session == nil {
		return
	}

	r := session.GetKeyRatchet(vc.UserID)
	if r != nil {
		c.installRatchet(vc.UserID, r)
	}
}

func (c *libdaveVoiceController) recognizedUserIDs(vc *VoiceConnection) []string {
	c.mu.Lock()
	seen := make(map[string]struct{}, len(c.knownUsers)+4)
	for userID := range c.knownUsers {
		seen[userID] = struct{}{}
	}
	c.mu.Unlock()

	if vc != nil && vc.UserID != "" {
		seen[vc.UserID] = struct{}{}
	}

	if vc != nil && vc.session != nil && vc.session.State != nil && vc.GuildID != "" {
		if guild, err := vc.session.State.Guild(vc.GuildID); err == nil && guild != nil {
			for _, voiceState := range guild.VoiceStates {
				if voiceState != nil && voiceState.UserID != "" {
					seen[voiceState.UserID] = struct{}{}
				}
			}
		}
	}

	out := make([]string, 0, len(seen))
	for userID := range seen {
		out = append(out, userID)
	}
	return out
}

// Discordgo - Discord bindings for Go
// Available at https://github.com/bwmarrin/discordgo

// Copyright 2015-2016 Bruce Marriner <bruce@sqls.net>.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains code related to Discord voice suppport

package discordgo

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	voiceGatewayVersion              = 8
	defaultDAVEProtocolVersion       = 1
	initialVoiceSequenceAck    int64 = -1

	voiceOpcodeDAVEExternalSenderPackage = 25
	voiceOpcodeDAVEKeyPackage            = 26
	voiceOpcodeDAVEMLSProposals          = 27
	voiceOpcodeDAVEMLSCommitWelcome      = 28
	voiceOpcodeDAVEMLSAnnounceCommit     = 29
	voiceOpcodeDAVEMLSWelcome            = 30
)

// ------------------------------------------------------------------------------------------------
// Code related to both VoiceConnection Websocket and UDP connections.
// ------------------------------------------------------------------------------------------------

// A VoiceConnection struct holds all the data and functions related to a Discord Voice Connection.
type VoiceConnection struct {
	sync.RWMutex

	Debug        bool // If true, print extra logging -- DEPRECATED
	LogLevel     int
	Ready        bool // If true, voice is ready to send/receive audio
	UserID       string
	GuildID      string
	ChannelID    string
	deaf         bool
	mute         bool
	speaking     bool
	reconnecting bool // If true, voice connection is trying to reconnect

	OpusSend chan []byte  // Chan for sending opus audio
	OpusRecv chan *Packet // Chan for receiving opus audio

	MaxDAVEProtocolVersion int

	wsConn  *websocket.Conn
	wsMutex sync.Mutex
	udpConn *net.UDPConn
	session *Session

	sessionID string
	token     string
	endpoint  string

	// Used to send a close signal to goroutines
	close chan struct{}

	// Used to allow blocking until connected
	connected chan bool

	// Used to pass the sessionid from onVoiceStateUpdate
	// sessionRecv chan string UNUSED ATM

	aead         cipher.AEAD
	nonceCounter uint32

	op4 voiceOP4
	op2 voiceOP2

	voiceSeqAck          int64
	voiceHeartbeatActive bool

	voiceSpeakingUpdateHandlers []VoiceSpeakingUpdateHandler
	voiceDAVEHandlers           []VoiceDAVEHandler
	daveController              VoiceDAVEController
}

// VoiceSpeakingUpdateHandler type provides a function definition for the
// VoiceSpeakingUpdate event
type VoiceSpeakingUpdateHandler func(vc *VoiceConnection, vs *VoiceSpeakingUpdate)

// VoiceDAVEHandler receives raw DAVE binary messages.
// Payload does not include the 2-byte sequence and 1-byte opcode headers.
type VoiceDAVEHandler func(vc *VoiceConnection, sequence uint16, opcode uint8, payload []byte)

// VoiceDAVEController is an optional callback set for handling DAVE negotiation
// and media frame transforms.
// Implementations are expected to provide MLS state and key management.
type VoiceDAVEController interface {
	PrepareTransition(vc *VoiceConnection, transitionID, protocolVersion int) (ready bool, err error)
	PrepareEpoch(vc *VoiceConnection, transitionID, protocolVersion int, epoch uint64) (ready bool, keyPackage []byte, err error)
	ExecuteTransition(vc *VoiceConnection, transitionID int) error

	ClientsConnected(vc *VoiceConnection, userIDs []string)
	ClientDisconnected(vc *VoiceConnection, userID string)

	HandleMLSExternalSender(vc *VoiceConnection, externalSender []byte) error
	HandleMLSProposals(vc *VoiceConnection, operationType uint8, payload []byte) (commit []byte, welcome []byte, err error)
	HandleMLSCommitTransition(vc *VoiceConnection, transitionID int, commit []byte) (ready bool, err error)
	HandleMLSWelcome(vc *VoiceConnection, transitionID int, welcome []byte) (ready bool, err error)

	EncryptOpus(vc *VoiceConnection, packet *Packet, opus []byte) ([]byte, error)
	DecryptOpus(vc *VoiceConnection, packet *Packet, opus []byte) ([]byte, error)
}

// Speaking sends a speaking notification to Discord over the voice websocket.
// This must be sent as true prior to sending audio and should be set to false
// once finished sending audio.
// b : Send true if speaking, false if not.
func (v *VoiceConnection) Speaking(b bool) (err error) {

	v.log(LogDebug, "called (%t)", b)

	type voiceSpeakingData struct {
		Speaking bool `json:"speaking"`
		Delay    int  `json:"delay"`
	}

	type voiceSpeakingOp struct {
		Op   int               `json:"op"` // Always 5
		Data voiceSpeakingData `json:"d"`
	}

	if v.wsConn == nil {
		return fmt.Errorf("no VoiceConnection websocket")
	}

	data := voiceSpeakingOp{5, voiceSpeakingData{b, 0}}
	v.wsMutex.Lock()
	err = v.wsConn.WriteJSON(data)
	v.wsMutex.Unlock()

	v.Lock()
	defer v.Unlock()
	if err != nil {
		v.speaking = false
		v.log(LogError, "Speaking() write json error, %s", err)
		return
	}

	v.speaking = b

	return
}

// ChangeChannel sends Discord a request to change channels within a Guild
// !!! NOTE !!! This function may be removed in favour of just using ChannelVoiceJoin
func (v *VoiceConnection) ChangeChannel(channelID string, mute, deaf bool) (err error) {

	v.log(LogInformational, "called")

	data := voiceChannelJoinOp{4, voiceChannelJoinData{&v.GuildID, &channelID, mute, deaf}}
	v.session.wsMutex.Lock()
	err = v.session.wsConn.WriteJSON(data)
	v.session.wsMutex.Unlock()
	if err != nil {
		return
	}
	v.ChannelID = channelID
	v.deaf = deaf
	v.mute = mute
	v.speaking = false

	return
}

// Disconnect disconnects from this voice channel and closes the websocket
// and udp connections to Discord.
func (v *VoiceConnection) Disconnect() (err error) {

	// Send a OP4 with a nil channel to disconnect
	v.Lock()
	if v.sessionID != "" {
		data := voiceChannelJoinOp{4, voiceChannelJoinData{&v.GuildID, nil, true, true}}
		v.session.wsMutex.Lock()
		err = v.session.wsConn.WriteJSON(data)
		v.session.wsMutex.Unlock()
		v.sessionID = ""
	}
	v.Unlock()

	// Close websocket and udp connections
	v.Close()

	v.log(LogInformational, "Deleting VoiceConnection %s", v.GuildID)

	v.session.Lock()
	delete(v.session.VoiceConnections, v.GuildID)
	v.session.Unlock()

	return
}

// Close closes the voice ws and udp connections
func (v *VoiceConnection) Close() {

	v.log(LogInformational, "called")

	v.Lock()
	defer v.Unlock()

	v.Ready = false
	v.speaking = false
	controller := v.daveController
	v.daveController = nil

	if v.close != nil {
		v.log(LogInformational, "closing v.close")
		close(v.close)
		v.close = nil
	}

	if v.udpConn != nil {
		v.log(LogInformational, "closing udp")
		err := v.udpConn.Close()
		if err != nil {
			v.log(LogError, "error closing udp connection, %s", err)
		}
		v.udpConn = nil
	}

	if v.wsConn != nil {
		v.log(LogInformational, "sending close frame")

		// To cleanly close a connection, a client should send a close
		// frame and wait for the server to close the connection.
		v.wsMutex.Lock()
		err := v.wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		v.wsMutex.Unlock()
		if err != nil {
			v.log(LogError, "error closing websocket, %s", err)
		}

		// TODO: Wait for Discord to actually close the connection.
		time.Sleep(1 * time.Second)

		v.log(LogInformational, "closing websocket")
		err = v.wsConn.Close()
		if err != nil {
			v.log(LogError, "error closing websocket, %s", err)
		}

		v.wsConn = nil
	}

	if controller != nil {
		closeDAVEController(controller)
	}
}

// AddHandler adds a Handler for VoiceSpeakingUpdate events.
func (v *VoiceConnection) AddHandler(h VoiceSpeakingUpdateHandler) {
	v.Lock()
	defer v.Unlock()

	v.voiceSpeakingUpdateHandlers = append(v.voiceSpeakingUpdateHandlers, h)
}

// AddDAVEHandler adds a handler for raw DAVE binary messages.
func (v *VoiceConnection) AddDAVEHandler(h VoiceDAVEHandler) {
	v.Lock()
	defer v.Unlock()

	v.voiceDAVEHandlers = append(v.voiceDAVEHandlers, h)
}

// SetDAVEController sets an optional controller for DAVE MLS and media-frame processing.
func (v *VoiceConnection) SetDAVEController(c VoiceDAVEController) {
	v.Lock()
	defer v.Unlock()
	v.daveController = c
}

// SendDAVE writes a raw DAVE binary message to the voice websocket.
// Client frames are [1-byte opcode][payload...].
func (v *VoiceConnection) SendDAVE(opcode uint8, payload []byte) error {
	if v.wsConn == nil {
		return fmt.Errorf("no VoiceConnection websocket")
	}

	frame := make([]byte, 1+len(payload))
	frame[0] = opcode
	copy(frame[1:], payload)

	v.wsMutex.Lock()
	err := v.wsConn.WriteMessage(websocket.BinaryMessage, frame)
	v.wsMutex.Unlock()
	if err != nil {
		v.log(LogError, "error writing DAVE opcode %d, %s", opcode, err)
		return err
	}

	return nil
}

// SendDAVEKeyPackage writes opcode 26 with an MLS key package.
func (v *VoiceConnection) SendDAVEKeyPackage(keyPackage []byte) error {
	if len(keyPackage) == 0 {
		return fmt.Errorf("empty DAVE key package")
	}
	return v.SendDAVE(voiceOpcodeDAVEKeyPackage, keyPackage)
}

// SendDAVECommitWelcome writes opcode 28 with a commit and optional welcome.
func (v *VoiceConnection) SendDAVECommitWelcome(commit, welcome []byte) error {
	if len(commit) == 0 {
		return fmt.Errorf("empty DAVE commit")
	}
	payload := make([]byte, len(commit)+len(welcome))
	copy(payload, commit)
	copy(payload[len(commit):], welcome)
	return v.SendDAVE(voiceOpcodeDAVEMLSCommitWelcome, payload)
}

// SendDAVEInvalidCommitWelcome writes opcode 31 for an unprocessable commit/welcome.
func (v *VoiceConnection) SendDAVEInvalidCommitWelcome(transitionID int) error {
	type invalidDAVEMessageData struct {
		TransitionID int `json:"transition_id"`
	}
	type invalidDAVEMessage struct {
		Op   int                    `json:"op"`
		Data invalidDAVEMessageData `json:"d"`
	}
	data := invalidDAVEMessage{
		Op:   31,
		Data: invalidDAVEMessageData{TransitionID: transitionID},
	}
	v.wsMutex.Lock()
	err := v.wsConn.WriteJSON(data)
	v.wsMutex.Unlock()
	return err
}

// Resume attempts to resume the active voice session using opcode 7.
func (v *VoiceConnection) Resume() error {
	if v.wsConn == nil {
		return fmt.Errorf("no VoiceConnection websocket")
	}
	data := voiceResumeOp{
		Op: 7,
		Data: voiceResumeData{
			ServerID:  v.GuildID,
			SessionID: v.sessionID,
			Token:     v.token,
			SeqAck:    v.voiceSeqAck,
		},
	}

	v.wsMutex.Lock()
	err := v.wsConn.WriteJSON(data)
	v.wsMutex.Unlock()
	return err
}

// VoiceSpeakingUpdate is a struct for a VoiceSpeakingUpdate event.
type VoiceSpeakingUpdate struct {
	UserID   string `json:"user_id"`
	SSRC     int    `json:"ssrc"`
	Speaking bool   `json:"speaking"`
}

// UnmarshalJSON accepts Discord's `speaking` payload as either a bool
// (legacy) or an integer bitmask (v8 voice). Any non-zero bitmask is
// treated as speaking=true.
func (v *VoiceSpeakingUpdate) UnmarshalJSON(data []byte) error {
	type alias VoiceSpeakingUpdate
	aux := &struct {
		Speaking json.RawMessage `json:"speaking"`
		*alias
	}{alias: (*alias)(v)}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if len(aux.Speaking) == 0 {
		return nil
	}

	var b bool
	if err := json.Unmarshal(aux.Speaking, &b); err == nil {
		v.Speaking = b
		return nil
	}

	var n int
	if err := json.Unmarshal(aux.Speaking, &n); err != nil {
		return fmt.Errorf("VoiceSpeakingUpdate.speaking: %w", err)
	}
	v.Speaking = n != 0
	return nil
}

// ------------------------------------------------------------------------------------------------
// Unexported Internal Functions Below.
// ------------------------------------------------------------------------------------------------

// A voiceOP4 stores the data for the voice operation 4 websocket event
// which provides us with the NaCl SecretBox encryption key
type voiceOP4 struct {
	SecretKey           [32]byte `json:"secret_key"`
	Mode                string   `json:"mode"`
	DAVEProtocolVersion int      `json:"dave_protocol_version"`
}

// A voiceOP2 stores the data for the voice operation 2 websocket event
// which is sort of like the voice READY packet
type voiceOP2 struct {
	SSRC              uint32        `json:"ssrc"`
	Port              int           `json:"port"`
	Modes             []string      `json:"modes"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	IP                string        `json:"ip"`
}

type voiceEvent struct {
	Operation int             `json:"op"`
	Sequence  *int64          `json:"seq,omitempty"`
	RawData   json.RawMessage `json:"d"`
}

type voiceHello struct {
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
}

type voiceHeartbeatData struct {
	Time   int64 `json:"t"`
	SeqAck int64 `json:"seq_ack,omitempty"`
}

type voiceTransitionData struct {
	TransitionID    int `json:"transition_id"`
	ProtocolVersion int `json:"protocol_version"`
}

type voiceExecuteTransitionData struct {
	TransitionID int `json:"transition_id"`
}

type voicePrepareEpochData struct {
	TransitionID    int    `json:"transition_id"`
	ProtocolVersion int    `json:"protocol_version"`
	Epoch           uint64 `json:"epoch"`
}

type voiceClientsConnectData struct {
	UserIDs []string `json:"user_ids"`
}

type voiceClientDisconnectData struct {
	UserID string `json:"user_id"`
}

// WaitUntilConnected waits for the Voice Connection to
// become ready, if it does not become ready it returns an err
func (v *VoiceConnection) waitUntilConnected() error {

	v.log(LogInformational, "called")

	i := 0
	for {
		v.RLock()
		ready := v.Ready
		v.RUnlock()
		if ready {
			return nil
		}

		if i > 10 {
			return fmt.Errorf("timeout waiting for voice")
		}

		time.Sleep(1 * time.Second)
		i++
	}
}

// Open opens a voice connection.  This should be called
// after VoiceChannelJoin is used and the data VOICE websocket events
// are captured.
func (v *VoiceConnection) open() (err error) {

	v.log(LogInformational, "called")

	v.Lock()
	defer v.Unlock()

	// Don't open a websocket if one is already open
	if v.wsConn != nil {
		v.log(LogWarning, "refusing to overwrite non-nil websocket")
		return
	}

	// TODO temp? loop to wait for the SessionID
	i := 0
	for {
		if v.sessionID != "" {
			break
		}

		if i > 20 { // only loop for up to 1 second total
			return fmt.Errorf("did not receive voice Session ID in time")
		}
		// Release the lock, so sessionID can be populated upon receiving a VoiceStateUpdate event.
		v.Unlock()
		time.Sleep(50 * time.Millisecond)
		i++
		v.Lock()
	}

	// Connect to VoiceConnection Websocket
	vg := "wss://" + strings.TrimSuffix(v.endpoint, ":80")
	if strings.Contains(vg, "?") {
		vg += fmt.Sprintf("&v=%d", voiceGatewayVersion)
	} else {
		vg += fmt.Sprintf("?v=%d", voiceGatewayVersion)
	}
	v.log(LogInformational, "connecting to voice endpoint %s", vg)
	v.wsConn, _, err = v.session.Dialer.Dial(vg, nil)
	if err != nil {
		v.log(LogWarning, "error connecting to voice endpoint %s, %s", vg, err)
		v.log(LogDebug, "voice struct: %#v\n", v)
		return
	}

	type voiceIdentifyData struct {
		ServerID               string `json:"server_id"`
		UserID                 string `json:"user_id"`
		SessionID              string `json:"session_id"`
		Token                  string `json:"token"`
		MaxDAVEProtocolVersion int    `json:"max_dave_protocol_version,omitempty"`
	}
	type voiceIdentifyOp struct {
		Op   int               `json:"op"` // Always 0
		Data voiceIdentifyData `json:"d"`
	}
	if v.MaxDAVEProtocolVersion == 0 {
		v.MaxDAVEProtocolVersion = defaultDAVEProtocolVersion
	}
	if v.daveController == nil {
		v.daveController = newDefaultDAVEController(v)
	}
	if !v.reconnecting {
		v.voiceSeqAck = initialVoiceSequenceAck
	}
	v.voiceHeartbeatActive = false

	identify := voiceIdentifyOp{
		Op: 0,
		Data: voiceIdentifyData{
			ServerID:               v.GuildID,
			UserID:                 v.UserID,
			SessionID:              v.sessionID,
			Token:                  v.token,
			MaxDAVEProtocolVersion: v.MaxDAVEProtocolVersion,
		},
	}

	v.wsMutex.Lock()
	err = v.wsConn.WriteJSON(identify)
	v.wsMutex.Unlock()
	if err != nil {
		v.log(LogWarning, "error sending init packet, %s", err)
		return
	}

	v.close = make(chan struct{})
	go v.wsListen(v.wsConn, v.close)

	// add loop/check for Ready bool here?
	// then return false if not ready?
	// but then wsListen will also err.

	return
}

// wsListen listens on the voice websocket for messages and passes them
// to the voice event handler.  This is automatically called by the Open func
func (v *VoiceConnection) wsListen(wsConn *websocket.Conn, close <-chan struct{}) {

	v.log(LogInformational, "called")

	for {
		messageType, message, err := v.wsConn.ReadMessage()
		if err != nil {
			// 4014 indicates a manual disconnection by someone in the guild;
			// we shouldn't reconnect.
			if websocket.IsCloseError(err, 4014) {
				v.log(LogInformational, "received 4014 manual disconnection")

				// Abandon the voice WS connection
				v.Lock()
				v.wsConn = nil
				v.Unlock()

				// Wait for VOICE_SERVER_UPDATE.
				// When the bot is moved by the user to another voice channel,
				// VOICE_SERVER_UPDATE is received after the code 4014.
				for i := 0; i < 5; i++ { // TODO: temp, wait for VoiceServerUpdate.
					<-time.After(1 * time.Second)

					v.RLock()
					reconnected := v.wsConn != nil
					v.RUnlock()
					if !reconnected {
						continue
					}
					v.log(LogInformational, "successfully reconnected after 4014 manual disconnection")
					return
				}

				// When VOICE_SERVER_UPDATE is not received, disconnect as usual.
				v.log(LogInformational, "disconnect due to 4014 manual disconnection")

				v.session.Lock()
				delete(v.session.VoiceConnections, v.GuildID)
				v.session.Unlock()

				v.Close()

				return
			}
			if websocket.IsCloseError(err, 4017) {
				v.log(LogError, "voice endpoint rejected connection with 4017 (E2EE/DAVE protocol required)")
				v.Close()
				return
			}

			// Detect if we have been closed manually. If a Close() has already
			// happened, the websocket we are listening on will be different to the
			// current session.
			v.RLock()
			sameConnection := v.wsConn == wsConn
			v.RUnlock()
			if sameConnection {

				v.log(LogError, "voice endpoint %s websocket closed unexpectedly, %s", v.endpoint, err)

				// Start reconnect goroutine then exit.
				go v.reconnect()
			}
			return
		}

		// Pass received message to voice event handler
		select {
		case <-close:
			return
		default:
			v.onEvent(messageType, message)
		}
	}
}

// wsEvent handles any voice websocket events. This is only called by the
// wsListen() function.
func (v *VoiceConnection) onEvent(messageType int, message []byte) {

	if messageType == websocket.BinaryMessage {
		v.onBinaryEvent(message)
		return
	}

	v.log(LogDebug, "received: %s", string(message))

	var e voiceEvent
	if err := json.Unmarshal(message, &e); err != nil {
		v.log(LogError, "unmarshall error, %s", err)
		return
	}
	if e.Sequence != nil {
		v.Lock()
		v.voiceSeqAck = *e.Sequence
		v.Unlock()
	}

	switch e.Operation {

	case 2: // READY

		if err := json.Unmarshal(e.RawData, &v.op2); err != nil {
			v.log(LogError, "OP2 unmarshall error, %s, %s", err, string(e.RawData))
			return
		}

		// Start the UDP connection
		err := v.udpOpen()
		if err != nil {
			v.log(LogError, "error opening udp connection, %s", err)
			return
		}

		// Start the opusSender.
		// TODO: Should we allow 48000/960 values to be user defined?
		// answer: no, 48k is required as per discord documentaiton and 960 is the most optimal frame size (based on testing)
		if v.OpusSend == nil {
			v.OpusSend = make(chan []byte, 2)
		}
		go v.opusSender(v.udpConn, v.close, v.OpusSend, 48000, 960)

		// Start the opusReceiver
		if !v.deaf {
			if v.OpusRecv == nil {
				v.OpusRecv = make(chan *Packet, 2)
			}

			go v.opusReceiver(v.udpConn, v.close, v.OpusRecv)
		}

		return

	case 6: // HEARTBEAT ACK
		// add code to use this to track latency?
		// TODO: maybe actually implement this, seems cool
		return

	case 4: // udp encryption secret key
		v.Lock()
		defer v.Unlock()

		v.op4 = voiceOP4{}
		if err := json.Unmarshal(e.RawData, &v.op4); err != nil {
			v.log(LogError, "OP4 unmarshall error, %s, %s", err, string(e.RawData))
			return
		}

		// TODO: error handling? meh
		block, _ := aes.NewCipher(v.op4.SecretKey[:])
		v.aead, _ = cipher.NewGCM(block)

		return

	case 9: // RESUMED
		return

	case 11: // CLIENTS CONNECT
		clients := voiceClientsConnectData{}
		if err := json.Unmarshal(e.RawData, &clients); err != nil {
			v.log(LogError, "OP11 unmarshall error, %s, %s", err, string(e.RawData))
			return
		}
		v.withDAVEController(func(c VoiceDAVEController) {
			c.ClientsConnected(v, clients.UserIDs)
		})
		return

	case 13: // CLIENT DISCONNECT
		client := voiceClientDisconnectData{}
		if err := json.Unmarshal(e.RawData, &client); err != nil {
			v.log(LogError, "OP13 unmarshall error, %s, %s", err, string(e.RawData))
			return
		}
		v.withDAVEController(func(c VoiceDAVEController) {
			c.ClientDisconnected(v, client.UserID)
		})
		return

	case 8: // HELLO
		hello := voiceHello{}
		if err := json.Unmarshal(e.RawData, &hello); err != nil {
			v.log(LogError, "OP8 unmarshall error, %s, %s", err, string(e.RawData))
			return
		}
		v.startHeartbeat(hello.HeartbeatInterval)
		return

	case 21: // DAVE Prepare Transition
		transition := voiceTransitionData{}
		if err := json.Unmarshal(e.RawData, &transition); err != nil {
			v.log(LogError, "OP21 unmarshall error, %s, %s", err, string(e.RawData))
			return
		}
		if v.handleDAVEPrepareTransition(transition.TransitionID, transition.ProtocolVersion) {
			v.sendDAVETransitionReady(transition.TransitionID)
		}
		return

	case 22: // DAVE Execute Transition
		transition := voiceExecuteTransitionData{}
		if err := json.Unmarshal(e.RawData, &transition); err != nil {
			v.log(LogError, "OP22 unmarshall error, %s, %s", err, string(e.RawData))
			return
		}
		v.handleDAVEExecuteTransition(transition.TransitionID)
		return

	case 24: // DAVE Prepare Epoch
		transition := voicePrepareEpochData{}
		if err := json.Unmarshal(e.RawData, &transition); err != nil {
			v.log(LogError, "OP24 unmarshall error, %s, %s", err, string(e.RawData))
			return
		}
		ready, keyPackage := v.handleDAVEPrepareEpoch(transition.TransitionID, transition.ProtocolVersion, transition.Epoch)
		if len(keyPackage) > 0 {
			if err := v.SendDAVEKeyPackage(keyPackage); err != nil {
				v.log(LogError, "error sending OP26 DAVE key package, %s", err)
			}
		}
		if ready {
			v.sendDAVETransitionReady(transition.TransitionID)
		}
		return

	case 5:
		voiceSpeakingUpdate := &VoiceSpeakingUpdate{}
		if err := json.Unmarshal(e.RawData, voiceSpeakingUpdate); err != nil {
			v.log(LogError, "OP5 unmarshall error, %s, %s", err, string(e.RawData))
			return
		}

		for _, h := range v.voiceSpeakingUpdateHandlers {
			h(v, voiceSpeakingUpdate)
		}
		v.withDAVEController(func(c VoiceDAVEController) {
			if observer, ok := c.(voiceDAVESpeakingObserver); ok {
				observer.HandleSpeakingUpdate(v, voiceSpeakingUpdate)
			}
		})
		return

	default:
		v.log(LogDebug, "unknown voice operation, %d, %s", e.Operation, string(e.RawData))
	}

	return
}

type voiceHeartbeatOp struct {
	Op   int                `json:"op"` // Always 3
	Data voiceHeartbeatData `json:"d"`
}

type voiceResumeData struct {
	ServerID  string `json:"server_id"`
	SessionID string `json:"session_id"`
	Token     string `json:"token"`
	SeqAck    int64  `json:"seq_ack,omitempty"`
}

type voiceResumeOp struct {
	Op   int             `json:"op"` // Always 7
	Data voiceResumeData `json:"d"`
}

// NOTE :: When a guild voice server changes how do we shut this down
// properly, so a new connection can be setup without fuss?
//
// wsHeartbeat sends regular heartbeats to voice Discord so it knows the client
// is still connected.  If you do not send these heartbeats Discord will
// disconnect the websocket connection after a few seconds.
func (v *VoiceConnection) wsHeartbeat(wsConn *websocket.Conn, close <-chan struct{}, i time.Duration) {

	if close == nil || wsConn == nil {
		return
	}

	var err error
	ticker := time.NewTicker(i * time.Millisecond)
	defer ticker.Stop()
	for {
		v.log(LogDebug, "sending heartbeat packet")
		v.RLock()
		seqAck := v.voiceSeqAck
		v.RUnlock()

		v.wsMutex.Lock()
		err = wsConn.WriteJSON(voiceHeartbeatOp{
			Op: 3,
			Data: voiceHeartbeatData{
				Time:   time.Now().UnixMilli(),
				SeqAck: seqAck,
			},
		})
		v.wsMutex.Unlock()
		if err != nil {
			v.log(LogError, "error sending heartbeat to voice endpoint %s, %s", v.endpoint, err)
			return
		}

		select {
		case <-ticker.C:
			// continue loop and send heartbeat
		case <-close:
			return
		}
	}
}

func (v *VoiceConnection) startHeartbeat(interval time.Duration) {
	if interval <= 0 {
		return
	}

	v.Lock()
	if v.voiceHeartbeatActive {
		v.Unlock()
		return
	}
	v.voiceHeartbeatActive = true
	wsConn := v.wsConn
	closeCh := v.close
	v.Unlock()

	go v.wsHeartbeat(wsConn, closeCh, interval)
}

func (v *VoiceConnection) sendDAVETransitionReady(transitionID int) {
	type voiceDAVETransitionReadyData struct {
		TransitionID int `json:"transition_id"`
	}
	type voiceDAVETransitionReadyOp struct {
		Op   int                          `json:"op"`
		Data voiceDAVETransitionReadyData `json:"d"`
	}

	ready := voiceDAVETransitionReadyOp{
		Op: 23,
		Data: voiceDAVETransitionReadyData{
			TransitionID: transitionID,
		},
	}

	v.wsMutex.Lock()
	err := v.wsConn.WriteJSON(ready)
	v.wsMutex.Unlock()
	if err != nil {
		v.log(LogError, "error sending OP23 DAVE transition ready, %s", err)
	}
}

func (v *VoiceConnection) withDAVEController(fn func(VoiceDAVEController)) {
	v.RLock()
	controller := v.daveController
	v.RUnlock()
	if controller == nil {
		return
	}
	fn(controller)
}

func (v *VoiceConnection) handleDAVEPrepareTransition(transitionID, protocolVersion int) bool {
	ready := true
	v.withDAVEController(func(c VoiceDAVEController) {
		controllerReady, err := c.PrepareTransition(v, transitionID, protocolVersion)
		if err != nil {
			v.log(LogError, "DAVE controller prepare transition failed, %s", err)
			ready = false
			return
		}
		ready = controllerReady
	})
	return ready
}

func (v *VoiceConnection) handleDAVEPrepareEpoch(transitionID, protocolVersion int, epoch uint64) (ready bool, keyPackage []byte) {
	ready = epoch > 1
	v.withDAVEController(func(c VoiceDAVEController) {
		controllerReady, controllerKeyPackage, err := c.PrepareEpoch(v, transitionID, protocolVersion, epoch)
		if err != nil {
			v.log(LogError, "DAVE controller prepare epoch failed, %s", err)
			ready = false
			return
		}
		ready = controllerReady
		keyPackage = controllerKeyPackage
	})
	return
}

func (v *VoiceConnection) handleDAVEExecuteTransition(transitionID int) {
	v.withDAVEController(func(c VoiceDAVEController) {
		if err := c.ExecuteTransition(v, transitionID); err != nil {
			v.log(LogError, "DAVE controller execute transition failed, %s", err)
		}
	})
}

func (v *VoiceConnection) transformOutboundOpus(packet *Packet, opus []byte) ([]byte, error) {
	var (
		out = opus
		err error
	)
	v.withDAVEController(func(c VoiceDAVEController) {
		out, err = c.EncryptOpus(v, packet, opus)
	})
	return out, err
}

func (v *VoiceConnection) transformInboundOpus(packet *Packet, opus []byte) ([]byte, error) {
	var (
		out = opus
		err error
	)
	v.withDAVEController(func(c VoiceDAVEController) {
		out, err = c.DecryptOpus(v, packet, opus)
	})
	return out, err
}

func (v *VoiceConnection) onBinaryEvent(message []byte) {
	// DAVE MLS opcodes are sent as binary payloads in v8 voice sessions.
	if len(message) < 3 {
		return
	}

	sequence := binary.BigEndian.Uint16(message[:2])
	opcode := message[2]
	payload := message[3:]

	v.Lock()
	v.voiceSeqAck = int64(sequence)
	handlers := append([]VoiceDAVEHandler{}, v.voiceDAVEHandlers...)
	v.Unlock()

	switch opcode {
	case voiceOpcodeDAVEExternalSenderPackage:
		v.withDAVEController(func(c VoiceDAVEController) {
			if err := c.HandleMLSExternalSender(v, payload); err != nil {
				v.log(LogError, "DAVE controller external sender handling failed, %s", err)
			}
		})

	case voiceOpcodeDAVEMLSProposals:
		if len(payload) < 1 {
			break
		}
		operationType := payload[0]
		proposalPayload := payload[1:]

		v.withDAVEController(func(c VoiceDAVEController) {
			commit, welcome, err := c.HandleMLSProposals(v, operationType, proposalPayload)
			if err != nil {
				v.log(LogError, "DAVE controller proposal handling failed, %s", err)
				return
			}
			if len(commit) == 0 {
				return
			}
			if err := v.SendDAVECommitWelcome(commit, welcome); err != nil {
				v.log(LogError, "error sending OP28 DAVE commit/welcome, %s", err)
			}
		})

	case voiceOpcodeDAVEMLSAnnounceCommit:
		if len(payload) < 2 {
			break
		}
		transitionID := int(binary.BigEndian.Uint16(payload[:2]))
		commit := payload[2:]

		v.withDAVEController(func(c VoiceDAVEController) {
			ready, err := c.HandleMLSCommitTransition(v, transitionID, commit)
			if err != nil {
				v.log(LogError, "DAVE controller commit transition handling failed, %s", err)
				return
			}
			if ready {
				v.sendDAVETransitionReady(transitionID)
			}
		})

	case voiceOpcodeDAVEMLSWelcome:
		if len(payload) < 2 {
			break
		}
		transitionID := int(binary.BigEndian.Uint16(payload[:2]))
		welcome := payload[2:]

		v.withDAVEController(func(c VoiceDAVEController) {
			ready, err := c.HandleMLSWelcome(v, transitionID, welcome)
			if err != nil {
				v.log(LogError, "DAVE controller welcome handling failed, %s", err)
				return
			}
			if ready {
				v.sendDAVETransitionReady(transitionID)
			}
		})
	}

	for _, h := range handlers {
		h(v, sequence, opcode, payload)
	}
}

// ------------------------------------------------------------------------------------------------
// Code related to the VoiceConnection UDP connection
// ------------------------------------------------------------------------------------------------

type voiceUDPData struct {
	Address string `json:"address"` // Public IP of machine running this code
	Port    uint16 `json:"port"`    // UDP Port of machine running this code
	Mode    string `json:"mode"`    // always "xsalsa20_poly1305"
}

type voiceUDPD struct {
	Protocol string       `json:"protocol"` // Always "udp" ?
	Data     voiceUDPData `json:"data"`
}

type voiceUDPOp struct {
	Op   int       `json:"op"` // Always 1
	Data voiceUDPD `json:"d"`
}

// udpOpen opens a UDP connection to the voice server and completes the
// initial required handshake.  This connection is left open in the session
// and can be used to send or receive audio.  This should only be called
// from voice.wsEvent OP2
func (v *VoiceConnection) udpOpen() (err error) {

	v.Lock()
	defer v.Unlock()

	if v.wsConn == nil {
		return fmt.Errorf("nil voice websocket")
	}

	if v.udpConn != nil {
		return fmt.Errorf("udp connection already open")
	}

	if v.close == nil {
		return fmt.Errorf("nil close channel")
	}

	if v.endpoint == "" {
		return fmt.Errorf("empty endpoint")
	}

	host := v.op2.IP + ":" + strconv.Itoa(v.op2.Port)
	addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		v.log(LogWarning, "error resolving udp host %s, %s", host, err)
		return
	}

	v.log(LogInformational, "connecting to udp addr %s", addr.String())
	v.udpConn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		v.log(LogWarning, "error connecting to udp addr %s, %s", addr.String(), err)
		return
	}

	// Create a 74 byte array to store the packet data
	sb := make([]byte, 74)
	binary.BigEndian.PutUint16(sb, 1)              // Packet type (0x1 is request, 0x2 is response)
	binary.BigEndian.PutUint16(sb[2:], 70)         // Packet length (excluding type and length fields)
	binary.BigEndian.PutUint32(sb[4:], v.op2.SSRC) // The SSRC code from the Op 2 VoiceConnection event

	// And send that data over the UDP connection to Discord.
	_, err = v.udpConn.Write(sb)
	if err != nil {
		v.log(LogWarning, "udp write error to %s, %s", addr.String(), err)
		return
	}

	// Create a 74-byte array and listen for the initial handshake response
	// from Discord.  Once we get it parse the IP and PORT information out
	// of the response.  This should be our public IP and PORT as Discord
	// saw us.
	rb := make([]byte, 74)
	rlen, _, err := v.udpConn.ReadFromUDP(rb)
	if err != nil {
		v.log(LogWarning, "udp read error, %s, %s", addr.String(), err)
		return
	}

	if rlen < 74 {
		v.log(LogWarning, "received udp packet too small")
		return fmt.Errorf("received udp packet too small")
	}

	// Loop over position 8 through 71 to grab the IP address.
	var ip string
	for i := 8; i < len(rb)-2; i++ {
		if rb[i] == 0 {
			break
		}
		ip += string(rb[i])
	}

	// Grab port from position 72 and 73
	port := binary.BigEndian.Uint16(rb[len(rb)-2:])

	// Take the data from above and send it back to Discord to finalize
	// the UDP connection handshake.

	// AEAD AES256-GCM (RTP Size)	aead_aes256_gcm_rtpsize	32-bit incremental integer value, appended to payload	Available (Preferred)
	data := voiceUDPOp{1, voiceUDPD{"udp", voiceUDPData{ip, port, "aead_aes256_gcm_rtpsize"}}}

	v.wsMutex.Lock()
	err = v.wsConn.WriteJSON(data)
	v.wsMutex.Unlock()
	if err != nil {
		v.log(LogWarning, "udp write error, %#v, %s", data, err)
		return
	}

	// start udpKeepAlive
	go v.udpKeepAlive(v.udpConn, v.close, 5*time.Second)
	// TODO: find a way to check that it fired off okay

	return
}

// udpKeepAlive sends a udp packet to keep the udp connection open
// This is still a bit of a "proof of concept"
func (v *VoiceConnection) udpKeepAlive(udpConn *net.UDPConn, close <-chan struct{}, i time.Duration) {

	if udpConn == nil || close == nil {
		return
	}

	var err error
	var sequence uint64

	packet := make([]byte, 8)

	ticker := time.NewTicker(i)
	defer ticker.Stop()
	for {

		binary.LittleEndian.PutUint64(packet, sequence)
		sequence++

		_, err = udpConn.Write(packet)
		if err != nil {
			v.log(LogError, "write error, %s", err)
			return
		}

		select {
		case <-ticker.C:
			// continue loop and send keepalive
		case <-close:
			return
		}
	}
}

// opusSender will listen on the given channel and send any
// pre-encoded opus audio to Discord.  Supposedly.
func (v *VoiceConnection) opusSender(udpConn *net.UDPConn, close <-chan struct{}, opus <-chan []byte, rate, size int) {

	if udpConn == nil || close == nil {
		return
	}

	// VoiceConnection is now ready to receive audio packets
	// TODO: this needs reviewing as I think there must be a better way.
	v.Lock()
	v.Ready = true
	v.Unlock()
	defer func() {
		v.Lock()
		v.Ready = false
		v.Unlock()
	}()

	var sequence uint16
	var timestamp uint32
	var recvbuf []byte
	var ok bool
	udpHeader := make([]byte, 12)
	nonce := make([]byte, 12)

	// build the parts that don't change in the udpHeader
	udpHeader[0] = 0x80
	udpHeader[1] = 0x78
	binary.BigEndian.PutUint32(udpHeader[8:], v.op2.SSRC)

	// start a send loop that loops until buf chan is closed
	ticker := time.NewTicker(time.Millisecond * time.Duration(size/(rate/1000)))
	defer ticker.Stop()
	for {

		// Get data from chan.  If chan is closed, return.
		select {
		case <-close:
			return
		case recvbuf, ok = <-opus:
			if !ok {
				return
			}
			// else, continue loop
		}

		v.RLock()
		speaking := v.speaking
		v.RUnlock()
		if !speaking {
			err := v.Speaking(true)
			if err != nil {
				v.log(LogError, "error sending speaking packet, %s", err)
			}
		}

		// Add sequence and timestamp to udpPacket
		binary.BigEndian.PutUint16(udpHeader[2:], sequence)
		binary.BigEndian.PutUint32(udpHeader[4:], timestamp)

		p := &Packet{
			SSRC:      v.op2.SSRC,
			Sequence:  sequence,
			Timestamp: timestamp,
		}
		payload, err := v.transformOutboundOpus(p, recvbuf)
		if err != nil {
			v.log(LogError, "outbound DAVE transform failed, %s", err)
			continue
		}

		// encrypt the opus data
		// add incrementing nonce counter as per discord's requirements
		binary.LittleEndian.PutUint32(nonce[:4], v.nonceCounter)
		v.nonceCounter++

		v.RLock()
		aead := v.aead
		v.RUnlock()
		if aead == nil {
			v.log(LogWarning, "voice session key not ready, dropping outbound frame")
			continue
		}

		sendbuf := aead.Seal(nil, nonce, payload, udpHeader)
		sendbuf = append(sendbuf, nonce[:4]...) // 4 byte nonce to ciphertext appended
		sendbuf = append(udpHeader, sendbuf...) // final

		// block here until we're exactly at the right time :)
		// Then send rtp audio packet to Discord over UDP
		select {
		case <-close:
			return
		case <-ticker.C:
			// continue
		}
		_, err = udpConn.Write(sendbuf)

		if err != nil {
			v.log(LogError, "udp write error, %s", err)
			v.log(LogDebug, "voice struct: %#v\n", v)
			return
		}

		if (sequence) == 0xFFFF {
			sequence = 0
		} else {
			sequence++
		}

		if (timestamp + uint32(size)) >= 0xFFFFFFFF {
			timestamp = 0
		} else {
			timestamp += uint32(size)
		}
	}
}

// A Packet contains the headers and content of a received voice packet.
type Packet struct {
	SSRC      uint32
	Sequence  uint16
	Timestamp uint32
	Type      []byte
	Opus      []byte
	PCM       []int16
}

// opusReceiver listens on the UDP socket for incoming packets
// and sends them across the given channel
// NOTE :: This function may change names later.
func (v *VoiceConnection) opusReceiver(udpConn *net.UDPConn, close <-chan struct{}, c chan *Packet) {

	if udpConn == nil || close == nil {
		return
	}

	recvbuf := make([]byte, 2048)
	var nonce [12]byte

	for {
		rlen, err := udpConn.Read(recvbuf)
		if err != nil {
			// Detect if we have been closed manually. If a Close() has already
			// happened, the udp connection we are listening on will be different
			// to the current session.
			v.RLock()
			sameConnection := v.udpConn == udpConn
			v.RUnlock()
			if sameConnection {

				v.log(LogError, "udp read error, %s, %s", v.endpoint, err)
				v.log(LogDebug, "voice struct: %#v\n", v)

				go v.reconnect()
			}
			return
		}

		select {
		case <-close:
			return
		default:
			// continue loop
		}

		// For now, skip anything except RTP v2 packets (audio).
		// RTP v2 => top two bits are 10 (0x80).
		if rlen < 12 || (recvbuf[0]&0xC0) != 0x80 {
			continue
		}

		// build a audio packet struct
		p := Packet{}
		p.Type = recvbuf[0:2]
		p.Sequence = binary.BigEndian.Uint16(recvbuf[2:4])
		p.Timestamp = binary.BigEndian.Uint32(recvbuf[4:8])
		p.SSRC = binary.BigEndian.Uint32(recvbuf[8:12])

		// RTP header parsing for *_rtpsize AEAD modes:
		// - base RTP header is 12 bytes + 4 bytes per CSRC (CC).
		// - if extension bit (X) is set, ONLY the 4-byte extension preamble is unencrypted/AAD;
		//   the extension payload is encrypted and must be stripped after decryption.
		cc := int(recvbuf[0] & 0x0F)
		hasExt := (recvbuf[0] & 0x10) != 0

		baseHeaderLen := 12 + (4 * cc)
		if rlen < baseHeaderLen {
			continue
		}

		aadLen := baseHeaderLen
		extPayloadBytes := 0
		if hasExt {
			if rlen < baseHeaderLen+4 {
				continue
			}
			// Extension length is in 32-bit words at the end of the extension preamble.
			extLenWords := int(binary.BigEndian.Uint16(recvbuf[baseHeaderLen+2 : baseHeaderLen+4]))
			extPayloadBytes = extLenWords * 4
			aadLen = baseHeaderLen + 4
		}

		if rlen < aadLen+4 {
			continue
		}

		// decrypt opus data
		payload := recvbuf[aadLen:rlen]
		if len(payload) < 4 {
			continue
		}
		nonceCounter := payload[len(payload)-4:]
		cipherTextPayload := payload[:len(payload)-4]

		binary.LittleEndian.PutUint32(nonce[:4], binary.LittleEndian.Uint32(nonceCounter))

		if v.aead == nil {
			continue
		}
		// AAD must cover the unencrypted header portion.
		if plain, err := v.aead.Open(nil, nonce[:], cipherTextPayload, recvbuf[:aadLen]); err == nil {
			// If header extensions are present, strip decrypted extension payload to get to Opus.
			if extPayloadBytes > 0 {
				if len(plain) < extPayloadBytes {
					continue
				}
				plain = plain[extPayloadBytes:]
			}
			decoded, err := v.transformInboundOpus(&p, plain)
			if err != nil {
				v.log(LogError, "inbound DAVE transform failed, %s", err)
				continue
			}
			p.Opus = decoded
		} else {
			continue
		}

		if c != nil {
			select {
			case c <- &p:
			case <-close:
				return
			}
		}
	}
}

// Reconnect will close down a voice connection then immediately try to
// reconnect to that session.
// NOTE : This func is messy and a WIP while I find what works.
// It will be cleaned up once a proven stable option is flushed out.
// aka: this is ugly shit code, please don't judge too harshly.
func (v *VoiceConnection) reconnect() {

	v.log(LogInformational, "called")

	v.Lock()
	if v.reconnecting {
		v.log(LogInformational, "already reconnecting to channel %s, exiting", v.ChannelID)
		v.Unlock()
		return
	}
	v.reconnecting = true
	v.Unlock()

	defer func() {
		v.Lock()
		v.reconnecting = false
		v.Unlock()
	}()

	// Close any currently open connections
	v.Close()

	wait := time.Duration(1)
	for {

		<-time.After(wait * time.Second)
		wait *= 2
		if wait > 600 {
			wait = 600
		}

		if v.session.DataReady == false || v.session.wsConn == nil {
			v.log(LogInformational, "cannot reconnect to channel %s with unready session", v.ChannelID)
			continue
		}

		v.log(LogInformational, "trying to reconnect to channel %s", v.ChannelID)

		_, err := v.session.ChannelVoiceJoin(v.GuildID, v.ChannelID, v.mute, v.deaf)
		if err == nil {
			v.log(LogInformational, "successfully reconnected to channel %s", v.ChannelID)
			return
		}

		v.log(LogInformational, "error reconnecting to channel %s, %s", v.ChannelID, err)

		// if the reconnect above didn't work lets just send a disconnect
		// packet to reset things.
		// Send a OP4 with a nil channel to disconnect
		data := voiceChannelJoinOp{4, voiceChannelJoinData{&v.GuildID, nil, true, true}}
		v.session.wsMutex.Lock()
		err = v.session.wsConn.WriteJSON(data)
		v.session.wsMutex.Unlock()
		if err != nil {
			v.log(LogError, "error sending disconnect packet, %s", err)
		}

	}
}

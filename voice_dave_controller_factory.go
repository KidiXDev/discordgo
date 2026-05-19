//go:build !libdave || !cgo
// +build !libdave !cgo

package discordgo

type voiceDAVESpeakingObserver interface {
	HandleSpeakingUpdate(vc *VoiceConnection, vs *VoiceSpeakingUpdate)
}

func newDefaultDAVEController(_ *VoiceConnection) VoiceDAVEController {
	return nil
}

func closeDAVEController(_ VoiceDAVEController) {}

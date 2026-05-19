//go:build libdave && cgo
// +build libdave,cgo

package dave

// #include <dave/dave.h>
import "C"

// Codec identifies a media codec for DAVE frame handling. libdave uses the
// codec to select which part of the frame is plaintext (unencrypted RTP/codec
// headers) vs. ciphertext (the media payload + DAVE AEAD tag).
type Codec int

const (
	CodecUnknown Codec = C.DAVE_CODEC_UNKNOWN
	CodecOpus    Codec = C.DAVE_CODEC_OPUS
	CodecVP8     Codec = C.DAVE_CODEC_VP8
	CodecVP9     Codec = C.DAVE_CODEC_VP9
	CodecH264    Codec = C.DAVE_CODEC_H264
	CodecH265    Codec = C.DAVE_CODEC_H265
	CodecAV1     Codec = C.DAVE_CODEC_AV1
)

// MediaType tells libdave whether a frame is audio or video so it can pick
// the matching per-codec cryptor. Cartridge bots only handle audio.
type MediaType int

const (
	MediaAudio MediaType = C.DAVE_MEDIA_TYPE_AUDIO
	MediaVideo MediaType = C.DAVE_MEDIA_TYPE_VIDEO
)

// LogSeverity mirrors DAVELoggingSeverity from libdave.
type LogSeverity int

const (
	LogVerbose LogSeverity = C.DAVE_LOGGING_SEVERITY_VERBOSE
	LogInfo    LogSeverity = C.DAVE_LOGGING_SEVERITY_INFO
	LogWarning LogSeverity = C.DAVE_LOGGING_SEVERITY_WARNING
	LogError   LogSeverity = C.DAVE_LOGGING_SEVERITY_ERROR
	LogNone    LogSeverity = C.DAVE_LOGGING_SEVERITY_NONE
)

// MaxSupportedProtocolVersion returns the highest DAVE protocol version the
// linked libdave can negotiate. Discord advertises the protocol version it
// wants to run at via voice opcode 24; clients must match or downgrade.
func MaxSupportedProtocolVersion() uint16 {
	return uint16(C.daveMaxSupportedProtocolVersion())
}

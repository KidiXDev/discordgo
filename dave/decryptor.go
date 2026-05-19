//go:build libdave && cgo
// +build libdave,cgo

package dave

// #include <dave/dave.h>
import "C"

import (
	"runtime"
	"sync"
	"unsafe"
)

// Decryptor wraps a DAVEDecryptorHandle, which is stateful per remote RTP
// stream. One decryptor per SSRC: Discord reuses SSRCs per-speaker, so when
// VoiceSpeakingUpdate tells us a new speaker's SSRC, we mint one.
//
// TransitionToKeyRatchet installs the ratchet for this decryptor but does
// NOT take ownership — the caller must keep the KeyRatchet alive until the
// Decryptor is closed or transitioned to a different ratchet.
type Decryptor struct {
	mu     sync.Mutex
	handle C.DAVEDecryptorHandle
	done   sync.Once
}

// NewDecryptor allocates an empty decryptor in passthrough mode. Call
// TransitionToKeyRatchet before Decrypt.
func NewDecryptor() *Decryptor {
	h := C.daveDecryptorCreate()
	d := &Decryptor{handle: h}
	runtime.SetFinalizer(d, func(d *Decryptor) { d.Close() })
	return d
}

// Close destroys the decryptor handle. Safe to call repeatedly.
func (d *Decryptor) Close() {
	d.done.Do(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.handle != nil {
			C.daveDecryptorDestroy(d.handle)
			d.handle = nil
		}
	})
}

// TransitionToKeyRatchet points the decryptor at a new key ratchet (e.g. after
// an MLS epoch change). The ratchet is not owned by the decryptor — the
// caller must keep the KeyRatchet alive.
func (d *Decryptor) TransitionToKeyRatchet(kr *KeyRatchet) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handle == nil {
		return
	}
	var h C.DAVEKeyRatchetHandle
	if kr != nil {
		h = kr.cHandle()
	}
	C.daveDecryptorTransitionToKeyRatchet(d.handle, h)
}

// TransitionToPassthroughMode flips the decryptor between encrypted and
// plaintext relay. Discord uses passthrough before the group is formed and
// when DAVE is disabled for a call.
func (d *Decryptor) TransitionToPassthroughMode(passthrough bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handle == nil {
		return
	}
	C.daveDecryptorTransitionToPassthroughMode(d.handle, C.bool(passthrough))
}

// MaxPlaintextSize returns the upper bound on plaintext size for a given
// ciphertext size. Use to pre-size the output buffer for Decrypt.
func (d *Decryptor) MaxPlaintextSize(mediaType MediaType, ciphertextLen int) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handle == nil {
		return 0
	}
	return int(C.daveDecryptorGetMaxPlaintextByteSize(
		d.handle,
		C.DAVEMediaType(mediaType),
		C.size_t(ciphertextLen),
	))
}

// Decrypt attempts to strip DAVE's AEAD envelope from ciphertext. On success
// returns the plaintext frame; on a passthrough frame or a key-ratchet miss
// returns an error (see ErrDecrypt* sentinels).
//
// The output slice is allocated by this call; the input is not mutated.
func (d *Decryptor) Decrypt(mediaType MediaType, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, ErrDecryptFailed
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handle == nil {
		return nil, ErrDecryptMissingCrypt
	}

	bufCap := C.daveDecryptorGetMaxPlaintextByteSize(
		d.handle,
		C.DAVEMediaType(mediaType),
		C.size_t(len(ciphertext)),
	)
	if bufCap == 0 {
		// Library couldn't compute a bound; fall back to input-sized buffer.
		bufCap = C.size_t(len(ciphertext))
	}
	out := make([]byte, int(bufCap))

	var written C.size_t
	code := C.daveDecryptorDecrypt(
		d.handle,
		C.DAVEMediaType(mediaType),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		C.size_t(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		bufCap,
		&written,
	)
	if err := decryptResultErr(code); err != nil {
		return nil, err
	}
	return out[:int(written)], nil
}

// Stats reports libdave's per-decryptor counters for the given media type.
func (d *Decryptor) Stats(mediaType MediaType) DecryptorStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handle == nil {
		return DecryptorStats{}
	}
	var s C.DAVEDecryptorStats
	C.daveDecryptorGetStats(d.handle, C.DAVEMediaType(mediaType), &s)
	return DecryptorStats{
		Passthrough:     uint64(s.passthroughCount),
		DecryptSuccess:  uint64(s.decryptSuccessCount),
		DecryptFailure:  uint64(s.decryptFailureCount),
		DecryptDuration: uint64(s.decryptDuration),
		DecryptAttempts: uint64(s.decryptAttempts),
		MissingKey:      uint64(s.decryptMissingKeyCount),
		InvalidNonce:    uint64(s.decryptInvalidNonceCount),
	}
}

// DecryptorStats mirrors the libdave DAVEDecryptorStats struct.
type DecryptorStats struct {
	Passthrough     uint64
	DecryptSuccess  uint64
	DecryptFailure  uint64
	DecryptDuration uint64
	DecryptAttempts uint64
	MissingKey      uint64
	InvalidNonce    uint64
}

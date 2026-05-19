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

// Encryptor wraps a DAVEEncryptorHandle used for outbound media-frame
// encryption.
type Encryptor struct {
	mu     sync.Mutex
	handle C.DAVEEncryptorHandle
	done   sync.Once
}

// NewEncryptor allocates a fresh encryptor handle.
func NewEncryptor() *Encryptor {
	h := C.daveEncryptorCreate()
	e := &Encryptor{handle: h}
	runtime.SetFinalizer(e, func(e *Encryptor) { e.Close() })
	return e
}

// Close destroys the encryptor handle. Safe to call repeatedly.
func (e *Encryptor) Close() {
	e.done.Do(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.handle != nil {
			C.daveEncryptorDestroy(e.handle)
			e.handle = nil
		}
	})
}

// SetKeyRatchet installs the ratchet used for outbound key derivation.
// The ratchet remains owned by the caller.
func (e *Encryptor) SetKeyRatchet(kr *KeyRatchet) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle == nil {
		return
	}
	var h C.DAVEKeyRatchetHandle
	if kr != nil {
		h = kr.cHandle()
	}
	C.daveEncryptorSetKeyRatchet(e.handle, h)
}

// SetPassthroughMode toggles pass-through mode.
func (e *Encryptor) SetPassthroughMode(passthrough bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle == nil {
		return
	}
	C.daveEncryptorSetPassthroughMode(e.handle, C.bool(passthrough))
}

// AssignSsrcToCodec maps an SSRC to a codec for frame packing.
func (e *Encryptor) AssignSsrcToCodec(ssrc uint32, codec Codec) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle == nil {
		return
	}
	C.daveEncryptorAssignSsrcToCodec(e.handle, C.uint32_t(ssrc), C.DAVECodec(codec))
}

// Encrypt wraps a plaintext frame in the DAVE envelope.
func (e *Encryptor) Encrypt(mediaType MediaType, ssrc uint32, frame []byte) ([]byte, error) {
	if len(frame) == 0 {
		return nil, ErrEncryptFailed
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle == nil {
		return nil, ErrEncryptMissingCrypt
	}

	bufCap := C.daveEncryptorGetMaxCiphertextByteSize(
		e.handle,
		C.DAVEMediaType(mediaType),
		C.size_t(len(frame)),
	)
	if bufCap == 0 {
		bufCap = C.size_t(len(frame) + 64)
	}

	out := make([]byte, int(bufCap))
	var written C.size_t
	code := C.daveEncryptorEncrypt(
		e.handle,
		C.DAVEMediaType(mediaType),
		C.uint32_t(ssrc),
		(*C.uint8_t)(unsafe.Pointer(&frame[0])),
		C.size_t(len(frame)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		bufCap,
		&written,
	)
	if err := encryptResultErr(code); err != nil {
		return nil, err
	}
	return out[:int(written)], nil
}

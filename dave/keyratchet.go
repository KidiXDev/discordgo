//go:build libdave && cgo
// +build libdave,cgo

package dave

// #include <dave/dave.h>
import "C"

import (
	"runtime"
	"sync"
)

// KeyRatchet wraps a DAVEKeyRatchetHandle. The ratchet carries the MLS
// exporter secret for a specific user; Decryptors consume it to derive per-
// frame AEAD keys.
//
// libdave's SetKeyRatchet / TransitionToKeyRatchet functions do NOT take
// ownership of the ratchet, so we must keep it alive until the consuming
// Decryptor/Encryptor is done with it. The caller owns the lifecycle; Close
// is idempotent.
type KeyRatchet struct {
	mu     sync.Mutex
	handle C.DAVEKeyRatchetHandle
	done   sync.Once
}

func newKeyRatchet(h C.DAVEKeyRatchetHandle) *KeyRatchet {
	kr := &KeyRatchet{handle: h}
	runtime.SetFinalizer(kr, func(kr *KeyRatchet) { kr.Close() })
	return kr
}

// Close destroys the ratchet handle. Must be called once the ratchet is no
// longer referenced by any Decryptor or Encryptor.
func (kr *KeyRatchet) Close() {
	kr.done.Do(func() {
		kr.mu.Lock()
		defer kr.mu.Unlock()
		if kr.handle != nil {
			C.daveKeyRatchetDestroy(kr.handle)
			kr.handle = nil
		}
	})
}

// cHandle exposes the raw handle for internal use by Decryptor/Encryptor.
// Returns nil if the ratchet has been closed.
func (kr *KeyRatchet) cHandle() C.DAVEKeyRatchetHandle {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	return kr.handle
}

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

// WelcomeResult wraps a DAVEWelcomeResultHandle. Carries the initial roster
// after we joined the MLS group. Always Close it.
type WelcomeResult struct {
	mu     sync.Mutex
	handle C.DAVEWelcomeResultHandle
	done   sync.Once
}

func newWelcomeResult(h C.DAVEWelcomeResultHandle) *WelcomeResult {
	r := &WelcomeResult{handle: h}
	runtime.SetFinalizer(r, func(r *WelcomeResult) { r.Close() })
	return r
}

// Close releases the handle. Safe to call multiple times.
func (r *WelcomeResult) Close() {
	r.done.Do(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.handle != nil {
			C.daveWelcomeResultDestroy(r.handle)
			r.handle = nil
		}
	})
}

// RosterMemberIDs returns the user IDs that form the initial group roster.
func (r *WelcomeResult) RosterMemberIDs() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == nil {
		return nil
	}
	var out *C.uint64_t
	var outLen C.size_t
	C.daveWelcomeResultGetRosterMemberIds(r.handle, &out, &outLen)
	if out == nil || outLen == 0 {
		return nil
	}
	defer C.daveFree(unsafe.Pointer(out))
	return copyU64Array(out, int(outLen))
}

// RosterMemberSignature returns the signature bytes for a specific roster
// member. Returns nil if the ID is not in the roster.
func (r *WelcomeResult) RosterMemberSignature(memberID uint64) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == nil {
		return nil
	}
	var out *C.uint8_t
	var outLen C.size_t
	C.daveWelcomeResultGetRosterMemberSignature(r.handle, C.uint64_t(memberID), &out, &outLen)
	if out == nil || outLen == 0 {
		return nil
	}
	defer C.daveFree(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen))
}

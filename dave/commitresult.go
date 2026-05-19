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

// CommitResult wraps a DAVECommitResultHandle. Carries the post-commit roster
// and failure/ignore flags. Always Close it.
type CommitResult struct {
	mu     sync.Mutex
	handle C.DAVECommitResultHandle
	done   sync.Once
}

func newCommitResult(h C.DAVECommitResultHandle) *CommitResult {
	r := &CommitResult{handle: h}
	runtime.SetFinalizer(r, func(r *CommitResult) { r.Close() })
	return r
}

// Close releases the handle. Safe to call multiple times.
func (r *CommitResult) Close() {
	r.done.Do(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.handle != nil {
			C.daveCommitResultDestroy(r.handle)
			r.handle = nil
		}
	})
}

// Failed returns true if libdave could not apply the commit.
func (r *CommitResult) Failed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == nil {
		return true
	}
	return bool(C.daveCommitResultIsFailed(r.handle))
}

// Ignored returns true if the commit should be treated as a no-op (e.g. we
// were already past this epoch).
func (r *CommitResult) Ignored() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == nil {
		return false
	}
	return bool(C.daveCommitResultIsIgnored(r.handle))
}

// RosterMemberIDs returns the user IDs in the group after the commit applies.
func (r *CommitResult) RosterMemberIDs() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == nil {
		return nil
	}
	var out *C.uint64_t
	var outLen C.size_t
	C.daveCommitResultGetRosterMemberIds(r.handle, &out, &outLen)
	if out == nil || outLen == 0 {
		return nil
	}
	defer C.daveFree(unsafe.Pointer(out))
	return copyU64Array(out, int(outLen))
}

// RosterMemberSignature returns the signature bytes for a specific roster
// member. Returns nil if the ID is not in the roster.
func (r *CommitResult) RosterMemberSignature(memberID uint64) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == nil {
		return nil
	}
	var out *C.uint8_t
	var outLen C.size_t
	C.daveCommitResultGetRosterMemberSignature(r.handle, C.uint64_t(memberID), &out, &outLen)
	if out == nil || outLen == 0 {
		return nil
	}
	defer C.daveFree(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen))
}

// copyU64Array copies a C-allocated uint64 array into a Go slice. The caller
// is responsible for freeing the C memory via daveFree.
func copyU64Array(ptr *C.uint64_t, n int) []uint64 {
	if ptr == nil || n <= 0 {
		return nil
	}
	out := make([]uint64, n)
	base := uintptr(unsafe.Pointer(ptr))
	step := unsafe.Sizeof(*ptr)
	for i := 0; i < n; i++ {
		p := (*C.uint64_t)(unsafe.Pointer(base + uintptr(i)*step))
		out[i] = uint64(*p)
	}
	return out
}

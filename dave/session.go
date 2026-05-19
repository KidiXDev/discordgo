//go:build libdave && cgo
// +build libdave,cgo

package dave

/*
#include <stdint.h>
#include <stdlib.h>
#include <dave/dave.h>

// Declared in callbacks.go; referenced here so session.go's preamble
// knows the trampoline signature when we pass it as a callback. The
// signature must match cgo's //export-generated prototype exactly
// (plain char*, not const char*).
extern void goDaveOnMLSFailure(char* source, char* reason, void* userData);

// Convenience wrapper so the Go side doesn't need to name-mangle the
// trampoline function-pointer cast for each daveSessionCreate call.
static inline DAVESessionHandle dave_session_create(const char* authSessionId, uintptr_t userData) {
    return daveSessionCreate(NULL, authSessionId, (DAVEMLSFailureCallback)goDaveOnMLSFailure, (void*)userData);
}
*/
import "C"

import (
	"runtime/cgo"
	"sync"
	"unsafe"
)

// Session wraps a DAVESessionHandle, which carries the MLS state for a single
// voice call. libdave sessions are not documented as thread-safe; we guard
// with a mutex so concurrent opcode handlers (welcome arrives while a commit
// is being processed, etc.) don't trip over each other.
type Session struct {
	mu sync.Mutex

	handle    C.DAVESessionHandle
	handleRef cgo.Handle // cgo handle exposing this Session to the C callback
	onFail    MLSFailureFunc
	destroy   sync.Once
}

// NewSession allocates a DAVESessionHandle and registers the failure callback.
// authSessionID is used by libdave to scope persistent key lifetimes — pass a
// stable per-voice-session string (e.g. the voice gateway session ID). onFail
// is invoked from a libdave thread; dispatch asynchronously if you need to
// touch heavy state.
func NewSession(authSessionID string, onFail MLSFailureFunc) *Session {
	s := &Session{onFail: onFail}
	s.handleRef = cgo.NewHandle(s)

	cAuth := C.CString(authSessionID)
	defer C.free(unsafe.Pointer(cAuth))

	s.handle = C.dave_session_create(cAuth, C.uintptr_t(s.handleRef))
	// No finalizer: cgo.NewHandle pins this Session for the lifetime of the
	// cgo.Handle, so GC cannot collect it until Destroy runs handleRef.Delete().
	// Destroy MUST be called by the owning code (VoiceConnection.Close).
	return s
}

// Destroy releases the underlying handle and unregisters the callback slot.
// Safe to call multiple times.
func (s *Session) Destroy() {
	s.destroy.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.handle != nil {
			C.daveSessionDestroy(s.handle)
			s.handle = nil
		}
		s.handleRef.Delete()
	})
}

// fireFailure is invoked from the C callback trampoline (goDaveOnMLSFailure).
func (s *Session) fireFailure(source, reason string) {
	if s.onFail != nil {
		s.onFail(source, reason)
	}
}

// Init sets the protocol version, MLS group ID, and the local user ID on the
// session. Must be called after NewSession and before any process* call.
func (s *Session) Init(protocolVersion uint16, groupID uint64, selfUserID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return
	}

	cUser := C.CString(selfUserID)
	defer C.free(unsafe.Pointer(cUser))

	C.daveSessionInit(s.handle, C.uint16_t(protocolVersion), C.uint64_t(groupID), cUser)
}

// Reset clears per-epoch state without destroying the session handle. Useful
// between voice reconnects on the same call.
func (s *Session) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return
	}
	C.daveSessionReset(s.handle)
}

// SetProtocolVersion updates the negotiated protocol version mid-session
// (Discord advertises version changes via voice opcode 24).
func (s *Session) SetProtocolVersion(v uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return
	}
	C.daveSessionSetProtocolVersion(s.handle, C.uint16_t(v))
}

// ProtocolVersion returns the version currently active on the session.
func (s *Session) ProtocolVersion() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return 0
	}
	return uint16(C.daveSessionGetProtocolVersion(s.handle))
}

// SetExternalSender installs Discord's external sender credentials. Received
// as a binary payload from voice opcode 25 (DAVE_MLS_EXTERNAL_SENDER).
func (s *Session) SetExternalSender(externalSender []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil || len(externalSender) == 0 {
		return
	}
	C.daveSessionSetExternalSender(
		s.handle,
		(*C.uint8_t)(unsafe.Pointer(&externalSender[0])),
		C.size_t(len(externalSender)),
	)
}

// MarshalledKeyPackage returns the MLS key package to send to Discord in
// response to opcode 26 (DAVE_MLS_KEY_PACKAGE). Caller owns the returned
// slice (it is copied out of libdave-allocated memory).
func (s *Session) MarshalledKeyPackage() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return nil
	}
	var out *C.uint8_t
	var outLen C.size_t
	C.daveSessionGetMarshalledKeyPackage(s.handle, &out, &outLen)
	if out == nil || outLen == 0 {
		return nil
	}
	defer C.daveFree(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen))
}

// LastEpochAuthenticator returns the authenticator bytes for the last MLS
// epoch. Useful for debugging group state divergence.
func (s *Session) LastEpochAuthenticator() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return nil
	}
	var out *C.uint8_t
	var outLen C.size_t
	C.daveSessionGetLastEpochAuthenticator(s.handle, &out, &outLen)
	if out == nil || outLen == 0 {
		return nil
	}
	defer C.daveFree(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen))
}

// ProcessProposals feeds proposals received from Discord (opcode 27 with
// optype=proposals) and returns the commit/welcome bytes we must send back.
// recognizedUserIDs is the set of user IDs our client trusts to be in the
// voice channel (i.e. users we've seen via VoiceStateUpdate). libdave uses
// these to decide whether to accept the proposal batch.
func (s *Session) ProcessProposals(proposals []byte, recognizedUserIDs []string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil || len(proposals) == 0 {
		return nil
	}

	cIDs, cIDsFree := cStringArray(recognizedUserIDs)
	defer cIDsFree()

	var out *C.uint8_t
	var outLen C.size_t
	C.daveSessionProcessProposals(
		s.handle,
		(*C.uint8_t)(unsafe.Pointer(&proposals[0])),
		C.size_t(len(proposals)),
		cIDs,
		C.size_t(len(recognizedUserIDs)),
		&out,
		&outLen,
	)
	if out == nil || outLen == 0 {
		return nil
	}
	defer C.daveFree(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen))
}

// ProcessCommit feeds a commit message from Discord (opcode 27 with
// optype=commit). Returns a CommitResult the caller must Close.
func (s *Session) ProcessCommit(commit []byte) *CommitResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil || len(commit) == 0 {
		return nil
	}
	h := C.daveSessionProcessCommit(
		s.handle,
		(*C.uint8_t)(unsafe.Pointer(&commit[0])),
		C.size_t(len(commit)),
	)
	if h == nil {
		return nil
	}
	return newCommitResult(h)
}

// ProcessWelcome feeds a welcome message (opcode 26) and returns a
// WelcomeResult the caller must Close.
func (s *Session) ProcessWelcome(welcome []byte, recognizedUserIDs []string) *WelcomeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil || len(welcome) == 0 {
		return nil
	}

	cIDs, cIDsFree := cStringArray(recognizedUserIDs)
	defer cIDsFree()

	h := C.daveSessionProcessWelcome(
		s.handle,
		(*C.uint8_t)(unsafe.Pointer(&welcome[0])),
		C.size_t(len(welcome)),
		cIDs,
		C.size_t(len(recognizedUserIDs)),
	)
	if h == nil {
		return nil
	}
	return newWelcomeResult(h)
}

// GetKeyRatchet returns a KeyRatchet handle for a specific user in the group.
// The ratchet is consumed by a Decryptor (or Encryptor) to produce per-frame
// keys via MLS-Exporter. Caller must Close the returned KeyRatchet.
func (s *Session) GetKeyRatchet(userID string) *KeyRatchet {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return nil
	}
	cUser := C.CString(userID)
	defer C.free(unsafe.Pointer(cUser))

	h := C.daveSessionGetKeyRatchet(s.handle, cUser)
	if h == nil {
		return nil
	}
	return newKeyRatchet(h)
}

// cStringArray converts a Go []string to a C const char** suitable for
// passing as recognizedUserIds. Returns a free func that releases all
// allocations.
func cStringArray(ss []string) (**C.char, func()) {
	if len(ss) == 0 {
		return nil, func() {}
	}
	// Allocate the array of char* pointers.
	arr := C.malloc(C.size_t(len(ss)) * C.size_t(unsafe.Sizeof(uintptr(0))))
	base := (*[1 << 28]*C.char)(arr)[:len(ss):len(ss)]
	for i, s := range ss {
		base[i] = C.CString(s)
	}
	return (**C.char)(arr), func() {
		for _, p := range base {
			C.free(unsafe.Pointer(p))
		}
		C.free(arr)
	}
}

//go:build libdave && cgo
// +build libdave,cgo

package dave

// This file carries the CGO #cgo directives (CFLAGS + LDFLAGS) for linking
// libdave. The C helper trampolines used from Go land (dave_session_create,
// dave_install_log_sink) live in the preamble of the file that calls them
// — cgo resolves C.xxx references against the preamble of the Go file
// where the reference appears, so a helper defined only here would be
// invisible to session.go or callbacks.go.

/*
#cgo CFLAGS: -I${SRCDIR}/libdave/cpp/includes
*/
import "C"

// Default LDFLAGS are omitted on purpose: libdave's transitive deps
// (mlspp, OpenSSL, nlohmann_json) are all static archives under
// dave/libdave/cpp/build/vcpkg_installed/<triplet>/lib. Consumers must
// pass the full archive list via CGO_LDFLAGS at build time — the
// goclaw Dockerfile globs it out of vcpkg_installed. Hardcoding
// -lssl/-lcrypto here would force the linker to look them up in the
// system library path, which doesn't carry them in our builder image.

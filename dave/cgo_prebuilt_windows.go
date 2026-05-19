//go:build libdave && cgo && windows
// +build libdave,cgo,windows

package dave

/*
#cgo CFLAGS: -I${SRCDIR}/build/windows/include
#cgo LDFLAGS: -L${SRCDIR}/build/windows/lib -ldave
*/
import "C"

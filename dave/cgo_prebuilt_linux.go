//go:build libdave && cgo && linux
// +build libdave,cgo,linux

package dave

/*
#cgo CFLAGS: -I${SRCDIR}/build/linux/include
#cgo LDFLAGS: -L${SRCDIR}/build/linux/lib -ldave
*/
import "C"

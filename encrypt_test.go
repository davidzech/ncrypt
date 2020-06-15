package ncrypt

import "testing"

func TestEncryptStruct(t *testing.T) {
	type primitives struct {
		Encrypt

		String     string
		Int        int
		Int64      int64
		Int32      int32
		Int16      int16
		Uint       uint
		Uint64     uint64
		Uint32     uint32
		Uint16     uint16
		Uintptr    uintptr
		Rune       rune
		Byte       byte
		Float64    float64
		Float32    float32
		Complex64  complex64
		Complex128 complex128
	}

}

package ncrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptStruct(t *testing.T) {
	type primitives struct {
		Encrypt

		String  string
		Int     int
		Int64   int64
		Int32   int32
		Int16   int16
		Int8    int8
		Uint    uint
		Uint64  uint64
		Uint32  uint32
		Uint16  uint16
		Uint8   uint8
		Uintptr uintptr
		// Rune       rune // alias for int32
		// Byte       byte // alias for uint8
		Float64    float64
		Float32    float32
		Complex64  complex64
		Complex128 complex128
		Slice      []byte
		Array      [8]byte
	}

	s := primitives{
		String:     "hello",
		Int:        -42,
		Int64:      math.MaxInt64,
		Int32:      math.MaxInt32,
		Int16:      math.MaxInt16,
		Int8:       0x6d,
		Uint:       42,
		Uint64:     math.MaxUint64,
		Uint32:     math.MaxUint32,
		Uint16:     math.MaxUint16,
		Uintptr:    uintptr(0x100),
		Float64:    math.MaxFloat64,
		Float32:    math.MaxFloat32,
		Complex64:  complex(float32(1), float32(1)),
		Complex128: complex(float64(1), float64(1)),
	}
	notASecret := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	b, _ := aes.NewCipher(notASecret)
	stream := cipher.NewCTR(b, notASecret)
	encryptStruct(stream, reflect.ValueOf(&s).Elem())
	stream = cipher.NewCTR(b, notASecret)
	decryptStruct(stream, reflect.ValueOf(&s).Elem())
	assert.Equal(t, s.Int, -42)
	assert.Equal(t, s.String, "hello")
}

func TestEncryptStructNested(t *testing.T) {

}

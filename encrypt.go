package ncrypt

import (
	"crypto/cipher"
	"reflect"
	"unsafe"
)

func encryptStruct(c cipher.Stream, s reflect.Value) {
	// we know s is a pointer to a struct, therefore all values can be set
	for i := 0; i < s.NumField(); i++ {
		field := s.Field(i)
		switch field.Kind() {
		case reflect.Int:
			bytes := (*[unsafe.Sizeof(int(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Int64:
			bytes := (*[unsafe.Sizeof(int64(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Int32:
			bytes := (*[unsafe.Sizeof(int32(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Int16:
			bytes := (*[unsafe.Sizeof(int16(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Int8:
			bytes := (*[unsafe.Sizeof(int8(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Uint:
			bytes := (*[unsafe.Sizeof(uint(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Uint64:
			bytes := (*[unsafe.Sizeof(uint64(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Uint32:
			bytes := (*[unsafe.Sizeof(uint32(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Uint16:
			bytes := (*[unsafe.Sizeof(uint16(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Uint8:
			bytes := (*[unsafe.Sizeof(uint8(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Uintptr:
			bytes := (*[unsafe.Sizeof(uintptr(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Float64:
			bytes := (*[unsafe.Sizeof(float64(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Float32:
			bytes := (*[unsafe.Sizeof(float32(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Complex64:
			bytes := (*[unsafe.Sizeof(complex64(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.Complex128:
			bytes := (*[unsafe.Sizeof(complex128(0))]byte)(unsafe.Pointer(field.UnsafeAddr()))[:] // potentially unsafe
			c.XORKeyStream(bytes, bytes)
		case reflect.String:
			bytes := []byte(field.String()) // strings are immutable so hacks are required to do this
			c.XORKeyStream(bytes, bytes)
			field.SetString(string(bytes))
		case reflect.Slice:

		}

	}
}

func encryptInt(c cipher.Stream, v *int) {

}

func decryptStruct(c cipher.Stream, s reflect.Value) {
	encryptStruct(c, s)
}

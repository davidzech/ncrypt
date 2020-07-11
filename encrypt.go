package ncrypt

import (
	"crypto/cipher"
	"reflect"
	"unsafe"
)

func encrypt(c cipher.Stream, v interface{}) {
	switch val := v.(type) {
	case *int:
		encryptInt(c, val)
	case *int64:
		encryptInt64(c, val)
	case *int32:
		encryptInt32(c, val)
	case *int16:
		encryptInt16(c, val)
	case *int8:
		encryptInt8(c, val)
	case *uint:
		encryptUint(c, val)
	case *uint64:
		encryptUint64(c, val)
	case *uint32:
		encryptUint32(c, val)
	case *uint16:
		encryptUint16(c, val)
	case *uint8:
		encryptUint8(c, val)
	case *float64:
		encryptFloat64(c, val)
	case *float32:
		encryptFloat32(c, val)
	case *complex128:
		encryptComplex128(c, val)
	case *complex64:
		encryptComplex64(c, val)
	case *string:
		encryptString(c, val)
	default:
		// is a slice or array or struct or interface
		rf := reflect.ValueOf(v)
		if rf.Kind() == reflect.Ptr {
			rf = rf.Elem()
		}
		if kind := rf.Kind(); kind == reflect.Slice {
			encryptSlice(c, v)
		} else if kind == reflect.Array {
			encryptArray(c, v)
		} else if kind == reflect.Struct {
			encryptStruct(c, v)
		}
	}
}

func encryptInt(c cipher.Stream, v *int) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptInt64(c cipher.Stream, v *int64) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptInt32(c cipher.Stream, v *int32) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptInt16(c cipher.Stream, v *int16) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptInt8(c cipher.Stream, v *int8) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptUint(c cipher.Stream, v *uint) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptUint64(c cipher.Stream, v *uint64) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptUint32(c cipher.Stream, v *uint32) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptUint16(c cipher.Stream, v *uint16) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}
func encryptUint8(c cipher.Stream, v *uint8) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptFloat64(c cipher.Stream, v *float64) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptFloat32(c cipher.Stream, v *float32) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptComplex128(c cipher.Stream, v *complex128) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptComplex64(c cipher.Stream, v *complex64) {
	bytes := (*[unsafe.Sizeof(*v)]byte)(unsafe.Pointer(v))[:]
	c.XORKeyStream(bytes, bytes)
}

func encryptString(c cipher.Stream, v *string) {
	buf := make([]byte, len(*v))
	c.XORKeyStream(buf, []byte(*v))
	*v = string(buf)
}

func encryptStruct(c cipher.Stream, st interface{}) {
	sp := reflect.ValueOf(st)
	s := sp.Elem()
	e, hasEncrypt := findEmbeddedEncrypt(sp)

	for i := 0; i < s.NumField(); i++ {
		field := s.Field(i)
		if hasEncrypt && field.Addr().Interface() == e {
			continue
		}
		encrypt(c, field.Addr().Interface())
	}
}

func encryptIterable(c cipher.Stream, itr interface{}) {
	val := reflect.ValueOf(itr)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	for i := 0; i < val.Len(); i++ {
		elem := val.Index(i).Addr()
		encrypt(c, elem.Interface())
	}
}

func encryptSlice(c cipher.Stream, sl interface{}) {
	encryptIterable(c, sl)
}

func encryptArray(c cipher.Stream, arr interface{}) {
	encryptIterable(c, arr)
}

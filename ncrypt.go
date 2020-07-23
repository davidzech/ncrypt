package ncrypt

import (
	"errors"
	"fmt"
	"io"
)

type Metadata struct {
}

func Encrypt(key []byte, v interface{}, opts ...interface{}) error {
	panic("not implemented")
}

func Decrypt(key []byte, v interface{}, opts ...interface{}) error {
	panic("not implemented")
}

func EncryptDetached(key []byte, v interface{}, opts ...interface{}) (Metadata, error) {
	panic("not implemented")
}

func DecryptDetached(key []byte, meta Metadata, v interface{}, opts ...interface{}) error {
	panic("not implemented")
}

type Encrypter interface {
}

type Decrypter interface {
}

func makeIV(random io.Reader, len int) (iv []byte, err error) {
	if err := func() error {
		iv = make([]byte, len)
		read, err := random.Read(iv)
		if err != nil {
			return err
		}
		if read != len {
			return errors.New("failed to read random bytes")
		}
		return nil
	}(); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %v", err)
	}
	return
}

// func initAESCTR(random io.Reader, metadata *Encrypt, key []byte) (cipher.Stream, error) {
// 	block, err := aes.NewCipher(key) // do key
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to initialize block cipher: %v", err)
// 	}
// 	iv, err := makeIV(random, block.BlockSize())
// 	if err != nil {
// 		return nil, err
// 	}
// 	stream := cipher.NewCTR(block, iv)
// 	return stream, nil
// }

// func isStructPointer(value reflect.Value) bool {
// 	return value.Kind() == reflect.Ptr && value.Elem().Kind() == reflect.Struct
// }

// func findEmbeddedEncrypt(val reflect.Value) (e *Encrypt, ok bool) {
// 	field := val.Elem().FieldByName("Encrypt")
// 	if !field.IsValid() ||
// 		field.Kind() != reflect.Struct ||
// 		field.Type() != reflect.TypeOf(Encrypt{}) {
// 		return nil, false
// 	}
// 	return field.Addr().Interface().(*Encrypt), true
// }

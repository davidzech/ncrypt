package ncrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
)

type Encrypter interface {
	Encrypt(interface{}) error
}

type Decrypter interface {
	Decrypt(interface{}) error
}

type Mode int

const (
	AESCTR Mode = iota
	AESGCM
)

type Context struct {
	Key  []byte
	Mode Mode
}

func (c *Context) key() []byte {
	return c.Key
}

func (c *Context) Decrypt(target interface{}) error {
	return nil
}

func makeIV(len int) (iv []byte, err error) {
	if err := func() error {
		iv = make([]byte, len)
		read, err := rand.Reader.Read(iv)
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

func (c *Context) Encrypt(target interface{}) error {
	v := reflect.ValueOf(target)
	if v.Kind() == reflect.Ptr && v.Elem().Kind() == reflect.Struct {
		s := v.Elem()
		// TODO: make sure the embedded fields are mutually exclusive
		if f := s.FieldByName("Encrypt"); !f.IsZero() {
			// found field, check if its the right type
			if f.Type() == reflect.TypeOf(Encrypt{}) {
				enc := f.Interface().(Encrypt)
				if enc.Encrypted {
					return errors.New("already encrypted")
				}
				block, err := aes.NewCipher(c.key()) // do key
				if err != nil {
					return fmt.Errorf("failed to initialize block cipher: %v", err)
				}
				iv, err := makeIV(block.BlockSize())
				if err != nil {
					return err
				}
				stream := cipher.NewCTR(block, iv)
				if err := encryptStruct(stream, s); err != nil {
					return fmt.Errorf("failed to encrypt struct: %w", err)
				}
				enc.IV = iv
				enc.Encrypted = true
			}
		}
		if !s.FieldByName("Seal").IsZero() {
			return errors.New("not implemented yet")
		}
	}
	return errors.New("value is not a pointer")
}

type AEADMetadata struct {
	Encrypted bool
	Nonce     []byte
	AuthTag   []byte
}

type StreamMetadata struct {
	Encrypted bool
	IV        []byte
}

type Seal struct {
	AEADMetadata
}

type Encrypt struct {
	StreamMetadata
}

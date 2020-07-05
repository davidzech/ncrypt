package ncrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
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
	Key    []byte
	Mode   Mode
	Random io.Reader
}

func (c *Context) key() []byte {
	return c.Key
}

func (c *Context) random() io.Reader {
	if c.Random == nil {
		c.Random = rand.Reader
	}
	return c.Random
}

func (c *Context) Decrypt(target interface{}) error {
	panic("not implemented")
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

func initAESCTR(random io.Reader, metadata *Encrypt, key []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key) // do key
	if err != nil {
		return nil, fmt.Errorf("failed to initialize block cipher: %v", err)
	}
	iv, err := makeIV(random, block.BlockSize())
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	return stream, nil
}

func isStructPointer(value reflect.Value) bool {
	return value.Kind() == reflect.Ptr && value.Elem().Kind() == reflect.Struct
}

func findEmbeddedEncrypt(val reflect.Value) (e *Encrypt, ok bool) {
	field := val.Elem().FieldByName("Encrypt")
	if !field.IsValid() ||
		field.Kind() != reflect.Struct ||
		field.Type() != reflect.TypeOf(Encrypt{}) {
		return nil, false
	}
	return field.Addr().Interface().(*Encrypt), true
}

func findEmbeddedSeal(val reflect.Value) (s *Seal, ok bool) {
	field := val.Elem().FieldByName("Seal")
	if !field.IsValid() ||
		field.Kind() != reflect.Struct ||
		field.Type() != reflect.TypeOf(Seal{}) {
		return nil, false
	}
	return field.Addr().Interface().(*Seal), true
}

func (c *Context) Encrypt(target interface{}) error {
	v := reflect.ValueOf(target)
	s := v.Elem()
	// TODO: make sure the embedded fields are mutually exclusive
	if enc, ok := findEmbeddedEncrypt(s); ok {
		// make sure we are exclusive
		if _, ok := findEmbeddedSeal(s); ok {
			return errors.New("ncrypt.Seal and ncrypt.Encrypt are mutually exclusive")
		}

		if enc.Encrypted {
			return errors.New("already encrypted")
		}

		stream, err := initAESCTR(c.random(), enc, c.key())
		if err != nil {
			enc.reset()
			return fmt.Errorf("failed to init cipher: %w", err)
		}
		encryptStruct(stream, s)
		enc.Encrypted = true
	}
	if _, ok := findEmbeddedSeal(s); ok {
		panic("not yet implemented")
	}
	return errors.New("value is not a struct pointer")
}

type Seal struct {
	Nonce     []byte
	AuthTag   []byte
	Encrypted bool
}

type Encrypt struct {
	IV        []byte
	Encrypted bool
}

func (e *Encrypt) reset() {
	*e = Encrypt{}
}

package ncrypt

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
	Key interface{}
}

func (c *Context) Decrypt(target interface{}) error {
	return nil
}

func (c *Context) Encrypt(target interface{}) error {
	return nil
}

type Metadata struct {
}

type Seal struct {
	Metadata
}

type Crypt struct {
	Metadata
}

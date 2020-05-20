package ncrypt

import "crypto/cipher"

// encryptStruct encrypts a pointer to a Struct
func (c *Context) encryptStruct(pStruct interface{}) error {
	return nil
}

func (c *Context) encryptString(pStr *string) error {
	return nil
}

func encryptInt(metadata *Metadata, scipher cipher.Stream, pInt *int) error {
	return nil
}

package ncrypt

import (
	"errors"
	"reflect"
)

// encryptStruct encrypts a pointer to a Struct
func (c *Context) encryptStruct(pStruct interface{}) error {
	v := reflect.ValueOf(pStruct)
	if v.Kind() == reflect.Ptr && v.Elem().Kind() == reflect.Struct {
		s := v.Elem()
		// TODO: make sure the embedded fields are mutually exclusive
		if f := s.FieldByName("Encrypt"); !f.IsZero() {
			// found field, check if its the right type
			if f.Type() == reflect.TypeOf(Encrypt{}) {
				enc := f.Interface().(Encrypt)

			}
		}
		if !s.FieldByName("Seal").IsZero() {
			return errors.New("not implemented yet")
		}
	}
	return errors.New("value is not a pointer")
}

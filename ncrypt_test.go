package ncrypt

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindEmbeddedEncrypt(t *testing.T) {
	type tc struct {
		name       string
		shouldFail bool
		val        interface{}
	}
	tcs := []tc{
		{
			name:       "embedded value",
			shouldFail: false,
			val: struct {
				Encrypt
			}{},
		},
	}
	for _, c := range tcs {
		t.Run(c.name, func(t *testing.T) {
			e, ok := findEmbeddedEncrypt(reflect.ValueOf(c.val))
			if !c.shouldFail {
				assert.NotNil(t, e)
				assert.True(t, ok)
			} else {
				assert.Nil(t, e)
				assert.False(t, ok)
			}
		})
	}
}

func TestFindEmbeddedSeal(t *testing.T) {

}

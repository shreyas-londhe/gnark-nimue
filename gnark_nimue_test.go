package gnark_nimue

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParser(t *testing.T) {
	pat := "👩‍💻🥷🏻👨‍💻 building 🔐🔒🗝️\u0000A10first\u0000S10second"
	patBytes := []byte(pat)
	fmt.Printf("patBytes: %s\n", patBytes)
	iopat := IOPattern{}
	err := iopat.Parse(patBytes)
	assert.Nil(t, err)
	fmt.Printf("iopat: %s\n", iopat.PPrint())

}

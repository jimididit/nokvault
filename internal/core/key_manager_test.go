package core

import (
	"testing"

	"github.com/jimididit/nokvault/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyManager_ParamsReturnsCopy(t *testing.T) {
	km := NewKeyManager()
	km.SetArgon2Params(&crypto.Argon2Params{
		Memory:      32768,
		Time:        2,
		Parallelism: 2,
		KeyLength:   crypto.DefaultKeyLength,
	})

	params := km.Params()
	require.NotNil(t, params)

	params.Memory = 1
	assert.Equal(t, uint32(32768), km.Params().Memory, "mutating returned params must not affect KeyManager")
}

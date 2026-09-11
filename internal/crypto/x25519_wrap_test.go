package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWrapUnwrap_MultiRecipient(t *testing.T) {
	id1, r1, err := GenerateIdentity()
	require.NoError(t, err)
	id2, r2, err := GenerateIdentity()
	require.NoError(t, err)
	id3, _, err := GenerateIdentity()
	require.NoError(t, err)

	fileKey := make([]byte, 32)
	_, err = rand.Read(fileKey)
	require.NoError(t, err)

	stanzas, err := WrapFileKey(fileKey, []*Recipient{r1, r2})
	require.NoError(t, err)
	require.Len(t, stanzas, 2)

	got1, err := UnwrapFileKey(stanzas, []*Identity{id1})
	require.NoError(t, err)
	require.True(t, bytes.Equal(fileKey, got1))

	got2, err := UnwrapFileKey(stanzas, []*Identity{id2})
	require.NoError(t, err)
	require.True(t, bytes.Equal(fileKey, got2))

	_, err = UnwrapFileKey(stanzas, []*Identity{id3})
	require.Error(t, err)
}

func TestWrap_RejectsTooManyRecipients(t *testing.T) {
	recs := make([]*Recipient, MaxRecipients+1)
	for i := range recs {
		_, r, err := GenerateIdentity()
		require.NoError(t, err)
		recs[i] = r
	}
	_, err := WrapFileKey(make([]byte, 32), recs)
	require.Error(t, err)
}

func TestMarshalParseStanzas(t *testing.T) {
	_, r, err := GenerateIdentity()
	require.NoError(t, err)
	stanzas, err := WrapFileKey(make([]byte, 32), []*Recipient{r})
	require.NoError(t, err)
	raw := MarshalStanzas(stanzas)
	require.Len(t, raw, X25519StanzaSize)
	parsed, err := ParseStanzas(raw, 1)
	require.NoError(t, err)
	require.Equal(t, stanzas, parsed)
}

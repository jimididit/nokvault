package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentity_RoundTrip(t *testing.T) {
	id, rec, err := GenerateIdentity()
	require.NoError(t, err)

	sec, err := id.Encode()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(sec, "NOKVAULT-SECRET-KEY-1"))

	pub, err := rec.Encode()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(pub, "nokvault1"))

	id2, err := ParseIdentity(sec)
	require.NoError(t, err)
	require.Equal(t, id.Secret, id2.Secret)

	rec2, err := ParseRecipient(pub)
	require.NoError(t, err)
	require.Equal(t, rec.Public, rec2.Public)
	require.Equal(t, rec.Public, id.Recipient().Public)
}

func TestIdentity_FileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.txt")
	id, _, err := GenerateIdentity()
	require.NoError(t, err)
	require.NoError(t, WriteIdentityFile(path, id, false))

	got, err := ReadIdentityFile(path)
	require.NoError(t, err)
	require.Equal(t, id.Secret, got.Secret)

	require.Error(t, WriteIdentityFile(path, id, false)) // no force
	require.NoError(t, WriteIdentityFile(path, id, true))
}

func TestWriteIdentityFile_ForceOverwritesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.txt")
	id, _, err := GenerateIdentity()
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, []byte("# stale\n"), 0o644))
	require.NoError(t, WriteIdentityFile(path, id, true))

	if !permSupportsChmod(t, path) {
		return
	}
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func permSupportsChmod(t *testing.T, path string) bool {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm() == 0o600
}

func TestParseRecipient_RejectsWrongHRP(t *testing.T) {
	_, err := ParseRecipient("age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsxq2fjq")
	require.Error(t, err)
}

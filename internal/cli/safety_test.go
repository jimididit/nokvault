package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimididit/nokvault/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestConfirmDestructive_AcceptsYes(t *testing.T) {
	var out bytes.Buffer
	err := confirmDestructive(strings.NewReader("yes\n"), &out, "Confirm?")
	require.NoError(t, err)
	require.Contains(t, out.String(), "Confirm?")
}

func TestConfirmDestructive_RejectsOther(t *testing.T) {
	err := confirmDestructive(strings.NewReader("y\n"), &bytes.Buffer{}, "Confirm?")
	require.Error(t, err)
}

func TestRequireConfirmation_YesFlagSkipsPrompt(t *testing.T) {
	err := requireConfirmation(true, false, strings.NewReader(""), &bytes.Buffer{})
	require.NoError(t, err)
}

func TestRequireConfirmation_NonInteractiveWithoutYes(t *testing.T) {
	err := requireConfirmation(false, false, strings.NewReader(""), &bytes.Buffer{})
	require.Error(t, err)
	var nv *utils.NokvaultError
	require.ErrorAs(t, err, &nv)
	require.Equal(t, "CONFIRMATION_REQUIRED", nv.Code)
}

func TestRequireConfirmation_InteractivePrompts(t *testing.T) {
	err := requireConfirmation(false, true, strings.NewReader("yes\n"), &bytes.Buffer{})
	require.NoError(t, err)
}

func TestRefuseIfExists_MissingOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.txt")
	require.NoError(t, refuseIfExists(path, false))
}

func TestRefuseIfExists_ExistsWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	err := refuseIfExists(path, false)
	require.Error(t, err)
	var nv *utils.NokvaultError
	require.ErrorAs(t, err, &nv)
	require.Equal(t, "OUTPUT_EXISTS", nv.Code)
}

func TestRefuseIfExists_ExistsWithForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	require.NoError(t, refuseIfExists(path, true))
}

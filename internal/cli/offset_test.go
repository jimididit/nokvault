package cli

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckedDataOffset(t *testing.T) {
	offset, err := checkedDataOffset(54)
	require.NoError(t, err)
	require.Equal(t, int64(54), offset)

	_, err = checkedDataOffset(math.MaxUint64)
	require.ErrorContains(t, err, "exceeds platform limit")
}

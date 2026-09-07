package cli

import (
	"fmt"

	"github.com/jimididit/nokvault/internal/config"
	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/crypto"
)

var runtimeConfig *config.Config

func SetRuntimeConfig(c *config.Config) { runtimeConfig = c }
func GetRuntimeConfig() *config.Config  { return runtimeConfig }
func ClearRuntimeConfig()               { runtimeConfig = nil }

func applyKDFConfig(km *core.KeyManager) error {
	cfg := GetRuntimeConfig()
	var params *crypto.Argon2Params
	if cfg == nil {
		params = crypto.DefaultArgon2Params()
	} else {
		params = &crypto.Argon2Params{
			Memory:      cfg.KeyDerivation.MemoryCost,
			Time:        cfg.KeyDerivation.TimeCost,
			Parallelism: cfg.KeyDerivation.Parallelism,
			KeyLength:   crypto.DefaultKeyLength,
		}
	}
	if err := core.ValidateKDFParams(params); err != nil {
		return fmt.Errorf("invalid key derivation config: %w", err)
	}
	km.SetArgon2Params(params)
	return nil
}

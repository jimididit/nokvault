package cli

import (
	"github.com/jimididit/nokvault/internal/config"
	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/crypto"
)

var runtimeConfig *config.Config

func SetRuntimeConfig(c *config.Config) { runtimeConfig = c }
func GetRuntimeConfig() *config.Config  { return runtimeConfig }
func ClearRuntimeConfig()               { runtimeConfig = nil }

func applyKDFConfig(km *core.KeyManager) {
	cfg := GetRuntimeConfig()
	if cfg == nil {
		km.SetArgon2Params(crypto.DefaultArgon2Params())
		return
	}
	km.SetParams(cfg.KeyDerivation.MemoryCost, cfg.KeyDerivation.TimeCost, cfg.KeyDerivation.Parallelism, crypto.DefaultKeyLength)
}

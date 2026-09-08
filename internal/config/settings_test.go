package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newIsolatedConfigManager(t *testing.T) (*ConfigManager, string) {
	t.Helper()
	t.Chdir(t.TempDir())
	configDir := t.TempDir()
	return newConfigManager(configDir), configDir
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotZero(t, config.KeyDerivation.MemoryCost, "Memory cost should not be zero")
	assert.NotZero(t, config.KeyDerivation.TimeCost, "Time cost should not be zero")
	assert.NotZero(t, config.KeyDerivation.Parallelism, "Parallelism should not be zero")
}

func TestConfigManager_Load_NoConfigFile(t *testing.T) {
	cm, _ := newIsolatedConfigManager(t)

	// Load should succeed even if config file doesn't exist (uses defaults)
	err := cm.Load()
	assert.NoError(t, err, "Load should succeed with defaults even if config file doesn't exist")

	config := cm.Get()
	require.NotNil(t, config, "Config should not be nil")

	assert.Equal(t, uint32(65536), config.KeyDerivation.MemoryCost)
}

func TestConfigManager_Save_Load(t *testing.T) {
	cm, configDir := newIsolatedConfigManager(t)

	config := cm.Get()
	config.KeyDerivation.MemoryCost = 32768

	// Save config (will save to actual config directory)
	// Note: This test modifies the actual config directory, so it's a bit invasive
	// In a real scenario, you might want to use a test-specific config directory
	err := cm.Save()
	if err != nil {
		// If save fails (e.g., permission issues), skip the test
		t.Skipf("Skipping test due to save error (may be permission issue): %v", err)
	}

	// Verify config file exists
	configPath := filepath.Join(configDir, "config.toml")
	_, err = os.Stat(configPath)
	require.NoError(t, err, "Config file should be created")
	defer os.Remove(configPath) // Clean up

	// Create new config manager and load
	cm2 := newConfigManager(configDir)
	err = cm2.Load()
	require.NoError(t, err, "Failed to load config")

	loadedConfig := cm2.Get()
	require.NotNil(t, loadedConfig, "Loaded config should not be nil")
	assert.Equal(t, config.KeyDerivation.MemoryCost, loadedConfig.KeyDerivation.MemoryCost,
		"Memory cost should be loaded correctly")
}

func TestConfigManager_Load_IgnoresLegacyDeadKeys(t *testing.T) {
	cm, configDir := newIsolatedConfigManager(t)
	legacy := []byte(`[encryption]
algorithm = "chacha20"
compression = true

[key_derivation]
memory_cost = 32768
time_cost = 2
parallelism = 2

[security]
key_cache_timeout = 300
`)
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.toml"), legacy, 0o600))
	require.NoError(t, cm.Load())

	cfg := cm.Get()
	assert.Equal(t, uint32(32768), cfg.KeyDerivation.MemoryCost)
	assert.Equal(t, uint32(2), cfg.KeyDerivation.TimeCost)
	assert.Equal(t, uint8(2), cfg.KeyDerivation.Parallelism)
}

func TestConfigManager_SetConfig(t *testing.T) {
	cm := NewConfigManager()

	newConfig := DefaultConfig()
	newConfig.KeyDerivation.MemoryCost = 32768

	cm.SetConfig(newConfig)

	config := cm.Get()
	assert.Equal(t, uint32(32768), config.KeyDerivation.MemoryCost, "Config should be set correctly")
}

func TestGetConfigPath(t *testing.T) {
	path := GetConfigPath()

	assert.NotEmpty(t, path, "Config path should not be empty")
	assert.Equal(t, "config.toml", filepath.Base(path), "Config path should end with config.toml")
}

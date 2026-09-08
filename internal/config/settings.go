package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	KeyDerivation KeyDerivationConfig `toml:"key_derivation" mapstructure:"key_derivation"`
}

// KeyDerivationConfig holds key derivation settings
type KeyDerivationConfig struct {
	MemoryCost  uint32 `toml:"memory_cost" mapstructure:"memory_cost"` // Memory cost in KB
	TimeCost    uint32 `toml:"time_cost" mapstructure:"time_cost"`     // Time cost
	Parallelism uint8  `toml:"parallelism" mapstructure:"parallelism"` // Parallelism factor
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		KeyDerivation: KeyDerivationConfig{
			MemoryCost:  65536, // 64 MB
			TimeCost:    3,
			Parallelism: 4,
		},
	}
}

// ConfigManager manages configuration loading and saving
type ConfigManager struct {
	viper     *viper.Viper
	config    *Config
	configDir string
}

// NewConfigManager creates a new config manager
func NewConfigManager() *ConfigManager {
	return newConfigManager(getConfigDir())
}

func newConfigManager(configDir string) *ConfigManager {
	v := viper.New()
	v.SetConfigType("toml")
	v.SetConfigName("config")

	// Set config paths
	v.AddConfigPath(configDir)
	v.AddConfigPath(".") // Current directory for .nokvault.toml

	return &ConfigManager{
		viper:     v,
		config:    DefaultConfig(),
		configDir: configDir,
	}
}

// Load loads configuration from files
func (cm *ConfigManager) Load() error {
	// Try to read global config
	if err := cm.viper.ReadInConfig(); err != nil {
		// If global config doesn't exist, that's okay - use defaults
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config: %w", err)
		}
	}

	// Try to read local config (.nokvault.toml)
	localViper := viper.New()
	localViper.SetConfigType("toml")
	localViper.SetConfigName(".nokvault")
	localViper.AddConfigPath(".")
	if err := localViper.ReadInConfig(); err == nil {
		// Merge local config over global
		if err := cm.viper.MergeConfigMap(localViper.AllSettings()); err != nil {
			return fmt.Errorf("failed to merge local config: %w", err)
		}
	}

	// Unmarshal into config struct
	if err := cm.viper.Unmarshal(cm.config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

// Save saves configuration to global config file
func (cm *ConfigManager) Save() error {
	if err := os.MkdirAll(cm.configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(cm.configDir, "config.toml")

	// Marshal config to TOML
	data, err := toml.Marshal(cm.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Get returns the current configuration
func (cm *ConfigManager) Get() *Config {
	return cm.config
}

// SetConfig allows setting configuration values programmatically
func (cm *ConfigManager) SetConfig(config *Config) {
	cm.config = config
}

// getConfigDir returns the configuration directory path
func getConfigDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory
		return "."
	}
	return filepath.Join(homeDir, ".config", "nokvault")
}

// GetConfigPath returns the path to the config file
func GetConfigPath() string {
	return filepath.Join(getConfigDir(), "config.toml")
}

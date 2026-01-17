package cli

import (
	"fmt"

	"github.com/jimididit/nokvault/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration settings",
	Long: `Manage nokvault configuration settings.

Configuration can be stored globally (~/.config/nokvault/config.toml) or
locally (.nokvault.toml in the current directory). Local config overrides global.`,
}

var (
	configShow  bool
	configInit  bool
	configGet   string
	configSet   string
	configValue string
)

func init() {
	configCmd.Flags().BoolVar(&configShow, "show", false, "Show current configuration")
	configCmd.Flags().BoolVar(&configInit, "init", false, "Initialize default configuration file")
	configCmd.Flags().StringVar(&configGet, "get", "", "Get a configuration value")
	configCmd.Flags().StringVar(&configSet, "set", "", "Set a configuration value")
	configCmd.Flags().StringVar(&configValue, "value", "", "Value for --set option")

	rootCmd.AddCommand(configCmd)
	configCmd.RunE = runConfig
}

func runConfig(cmd *cobra.Command, args []string) error {
	cm := config.NewConfigManager()

	if configInit {
		// Initialize default config
		if err := cm.Save(); err != nil {
			PrintError(fmt.Sprintf("Failed to save config: %v", err))
			return err
		}
		PrintSuccess(fmt.Sprintf("Configuration initialized at: %s", config.GetConfigPath()))
		return nil
	}

	// Load config
	if err := cm.Load(); err != nil {
		PrintInfo("No configuration file found. Use 'nokvault config --init' to create one.")
	}

	cfg := cm.Get()

	if configShow {
		// Show full config
		fmt.Println("Current Configuration:")
		fmt.Printf("  Encryption Algorithm: %s\n", cfg.Encryption.Algorithm)
		fmt.Printf("  Compression: %v\n", cfg.Encryption.Compression)
		fmt.Printf("  Preserve Metadata: %v\n", cfg.Encryption.PreserveMetadata)
		fmt.Printf("  Key Derivation: %s\n", cfg.KeyDerivation.Algorithm)
		fmt.Printf("  Memory Cost: %d KB\n", cfg.KeyDerivation.MemoryCost)
		fmt.Printf("  Time Cost: %d\n", cfg.KeyDerivation.TimeCost)
		fmt.Printf("  Parallelism: %d\n", cfg.KeyDerivation.Parallelism)
		fmt.Printf("  Secure Delete: %v\n", cfg.Security.SecureDelete)
		fmt.Printf("  Delete Passes: %d\n", cfg.Security.DeletePasses)
		fmt.Printf("  Key Cache Timeout: %d seconds\n", cfg.Security.KeyCacheTimeout)
		return nil
	}

	if configGet != "" {
		// Get specific config value
		switch configGet {
		case "algorithm":
			fmt.Println(cfg.Encryption.Algorithm)
		case "compression":
			fmt.Println(cfg.Encryption.Compression)
		case "preserve_metadata":
			fmt.Println(cfg.Encryption.PreserveMetadata)
		case "memory_cost":
			fmt.Println(cfg.KeyDerivation.MemoryCost)
		case "time_cost":
			fmt.Println(cfg.KeyDerivation.TimeCost)
		case "parallelism":
			fmt.Println(cfg.KeyDerivation.Parallelism)
		case "secure_delete":
			fmt.Println(cfg.Security.SecureDelete)
		case "delete_passes":
			fmt.Println(cfg.Security.DeletePasses)
		default:
			PrintError(fmt.Sprintf("Unknown configuration key: %s", configGet))
			return fmt.Errorf("unknown key: %s", configGet)
		}
		return nil
	}

	if configSet != "" {
		// Set specific config value
		if configValue == "" {
			PrintError("--value is required when using --set")
			return fmt.Errorf("--value required")
		}

		// TODO: Implement setting individual values
		PrintInfo("Setting individual config values is not yet implemented")
		PrintInfo("Edit the config file directly or use 'nokvault config --init' to reset")
		return nil
	}

	// Show help if no action specified
	cmd.Help()
	return nil
}

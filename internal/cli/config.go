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
	configShow bool
	configInit bool
	configGet  string
)

func init() {
	configCmd.Flags().BoolVar(&configShow, "show", false, "Show current configuration")
	configCmd.Flags().BoolVar(&configInit, "init", false, "Initialize default configuration file")
	configCmd.Flags().StringVar(&configGet, "get", "", "Get a configuration value")

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
		fmt.Println("Current configuration for new encryptions:")
		fmt.Println("  Key Derivation: argon2id")
		fmt.Printf("  Memory Cost: %d KB\n", cfg.KeyDerivation.MemoryCost)
		fmt.Printf("  Time Cost: %d\n", cfg.KeyDerivation.TimeCost)
		fmt.Printf("  Parallelism: %d\n", cfg.KeyDerivation.Parallelism)
		return nil
	}

	if configGet != "" {
		switch configGet {
		case "memory_cost":
			fmt.Println(cfg.KeyDerivation.MemoryCost)
		case "time_cost":
			fmt.Println(cfg.KeyDerivation.TimeCost)
		case "parallelism":
			fmt.Println(cfg.KeyDerivation.Parallelism)
		default:
			PrintError(fmt.Sprintf("Unknown configuration key: %s", configGet))
			return fmt.Errorf("unknown key: %s", configGet)
		}
		return nil
	}

	// Show help if no action specified
	cmd.Help()
	return nil
}

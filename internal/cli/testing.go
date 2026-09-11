package cli

import (
	"time"

	"github.com/spf13/cobra"
)

// ResetCLIStateForTest clears package-level Cobra flag bindings and args.
// Integration tests share a single rootCmd; without this, flag values leak
// across tests (e.g. leftover --output / --password).
func ResetCLIStateForTest() {
	ClearRuntimeConfig()
	rootCmd.SetArgs(nil)
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	rootCmd.SilenceErrors = false
	rootCmd.SilenceUsage = false
	jsonOutput = false
	if flag := rootCmd.PersistentFlags().Lookup("json"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}
	var resetHelpAndVersion func(*cobra.Command)
	resetHelpAndVersion = func(cmd *cobra.Command) {
		for _, name := range []string{"help", "version"} {
			if flag := cmd.Flags().Lookup(name); flag != nil {
				_ = flag.Value.Set("false")
				flag.Changed = false
			}
		}
		for _, child := range cmd.Commands() {
			resetHelpAndVersion(child)
		}
	}
	resetHelpAndVersion(rootCmd)
	resetReporter()

	encryptOutput = ""
	encryptPassword = ""
	encryptKeyfile = ""
	encryptNoPrompt = false
	encryptDryRun = false
	encryptVerbose = false
	encryptCompress = false
	encryptNoCompress = false

	decryptOutput = ""
	decryptPassword = ""
	decryptKeyfile = ""
	decryptNoPrompt = false
	decryptDryRun = false
	decryptVerbose = false
	decryptPreserveMode = false

	protectOutput = ""
	protectPassword = ""
	protectKeyfile = ""
	protectNoPrompt = false
	protectDryRun = false
	protectVerbose = false

	secureDeletePasses = 3
	secureDeleteVerbose = false
	secureDeleteYes = false
	secureDeleteDryRun = false

	encryptForce = false
	decryptForce = false
	decryptStrict = false

	watchAutoEncrypt = false
	watchDelay = 2 * time.Second
	watchExclude = nil
	watchRecursive = true
	watchVerbose = false
	watchPassword = ""
	watchKeyfile = ""
	watchNoPrompt = false

	rotateKeyOldPassword = ""
	rotateKeyNewPassword = ""
	rotateKeyOldKeyfile = ""
	rotateKeyNewKeyfile = ""
	rotateKeyNoPrompt = false
	rotateKeyVerbose = false

	scheduleInterval = time.Hour
	schedulePassword = ""
	scheduleKeyfile = ""
	scheduleNoPrompt = false
	scheduleVerbose = false
	scheduleCompress = false

	configShow = false
	configInit = false
	configGet = ""

	keygenOut = "nokvault-identity.txt"
	keygenPublicOut = ""
	keygenForce = false

	encryptRecipients = nil
	decryptIdentities = nil
}

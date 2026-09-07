package cli

import "time"

// ResetCLIStateForTest clears package-level Cobra flag bindings and args.
// Integration tests share a single rootCmd; without this, flag values leak
// across tests (e.g. leftover --output / --password).
func ResetCLIStateForTest() {
	ClearRuntimeConfig()
	rootCmd.SetArgs(nil)

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

	protectOutput = ""
	protectPassword = ""
	protectKeyfile = ""
	protectNoPrompt = false
	protectDryRun = false
	protectVerbose = false

	secureDeletePasses = 3
	secureDeleteVerbose = false

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
	configSet = ""
	configValue = ""
}

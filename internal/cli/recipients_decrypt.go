package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/crypto"
	"github.com/jimididit/nokvault/internal/utils"
)

// loadIdentities loads identity files and parses them.
func loadIdentities(paths []string) ([]*crypto.Identity, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one identity is required")
	}
	identities := make([]*crypto.Identity, 0, len(paths))
	for _, path := range paths {
		id, err := crypto.ReadIdentityFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read identity %q: %w", path, err)
		}
		identities = append(identities, id)
	}
	return identities, nil
}

// decryptFileWithIdentities decrypts a v4 file using identities.
func decryptFileWithIdentities(inputPath, outputPath string, identities []*crypto.Identity, encryptionService *core.EncryptionService) error {
	if decryptVerbose {
		PrintInfo(fmt.Sprintf("Decrypting file with %d identity(s): %s", len(identities), inputPath))
	}

	// Open input file
	// #nosec G304 -- runDecrypt validates the user-selected input path before this open.
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read header with metadata and stanzas
	fileHandler := core.NewFileHandler()
	header, metadata, aad, stanzas, err := fileHandler.ReadHeaderWithMetadata(inputFile)
	if err != nil {
		PrintError("Invalid nokvault file format")
		return utils.NewError(utils.ErrInvalidFormat.Code, "Invalid nokvault file format", err)
	}

	if header.Version != core.Version4 {
		return fmt.Errorf("expected v4 recipient vault, got v%d", header.Version)
	}

	// Unwrap file key using identities
	fileKey, err := crypto.UnwrapFileKey(stanzas, identities)
	if err != nil {
		return utils.NewErrorWithHint(utils.ErrDecryptionFailed.Code, "No identity could decrypt this vault", err, "Verify that you have the correct identity file for this vault.")
	}
	defer utils.ZeroizeKey(fileKey)

	dataOffset, err := checkedDataOffset(header.DataOffset)
	if err != nil {
		return err
	}
	if _, err := inputFile.Seek(dataOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek encrypted data: %w", err)
	}

	// Ensure output directory exists
	if outputDir := filepath.Dir(outputPath); outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0700); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if err := refuseIfExists(outputPath, decryptForce); err != nil {
		PrintError(err.Error())
		return err
	}

	atomicWrite := utils.AtomicWriteFuncNoReplace
	if decryptForce {
		atomicWrite = utils.AtomicWriteFunc
	}
	compressionService := core.NewCompressionService()
	if err := atomicWrite(outputPath, 0o600, func(outputFile *os.File) error {
		if err := decryptVaultToOutput(outputFile, inputFile, fileKey, header, aad, encryptionService, compressionService); err != nil {
			return utils.NewErrorWithHint(utils.ErrDecryptionFailed.Code, "Decryption failed - corrupted file or wrong identity", err, "Verify that the vault was encrypted for your identity.")
		}
		return nil
	}); err != nil {
		return err
	}

	// Restore metadata if available
	if metadata != nil {
		if err := fileHandler.WriteMetadata(outputPath, metadata, decryptPreserveMode); err != nil {
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Could not restore metadata: %v", err))
			}
		}
	}

	if JSONEnabled() {
		return EmitResult("decrypt", DecryptResult{
			Input: inputPath, Output: outputPath, TargetKind: "file",
			Processed: 1, Succeeded: 1, Force: decryptForce, Strict: decryptStrict,
		})
	}
	PrintSuccess(fmt.Sprintf("Decrypted: %s -> %s", inputPath, outputPath))
	return nil
}

// decryptDirectoryWithIdentities decrypts a directory of v4 vaults using identities.
func decryptDirectoryWithIdentities(inputPath, outputPath string, identities []*crypto.Identity, encryptionService *core.EncryptionService) error {
	fileHandler := core.NewFileHandler()
	result := DecryptResult{
		Input: inputPath, Output: outputPath, TargetKind: "directory",
		Force: decryptForce, Strict: decryptStrict,
	}

	// Count vault files for progress
	totalFiles := 0
	if err := fileHandler.WalkDirectory(inputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && utils.IsVaultPath(path) {
			totalFiles++
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to count vault files: %w", err)
	}

	if totalFiles == 0 {
		if JSONEnabled() {
			return EmitResult("decrypt", result)
		}
		PrintInfo("No encrypted vault files found in directory")
		return nil
	}

	if decryptVerbose {
		PrintInfo(fmt.Sprintf("Decrypting directory with %d identity(s): %s", len(identities), inputPath))
		PrintInfo(fmt.Sprintf("Found %d vault files", totalFiles))
	}

	if err := utils.ValidateNoSymlinkComponents(outputPath); err != nil {
		return err
	}

	if err := fileHandler.EnsureDirectory(outputPath); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if err := utils.ValidateNoSymlinkComponents(outputPath); err != nil {
		return err
	}

	progressBar := newOperationProgressBar(int64(totalFiles), "Decrypting files")
	currentFile := 0
	compressionService := core.NewCompressionService()

	walkErr := fileHandler.WalkDirectory(inputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing %s: %w", path, err)
		}

		if info.IsDir() {
			return nil
		}

		if !utils.IsVaultPath(path) {
			return nil
		}

		currentFile++
		result.Processed++

		relPath, err := fileHandler.GetRelativePath(inputPath, path)
		if err != nil {
			progressBar.Increment(1)
			if decryptStrict {
				return fmt.Errorf("failed to get relative path for %s: %w", path, err)
			}
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Skipping %s: %v", path, err))
			}
			return nil
		}

		stripped, ok := utils.StripVaultExt(relPath)
		if !ok {
			stripped = relPath + ".decrypted"
		}

		outPath, err := utils.SafeJoin(outputPath, stripped)
		if err != nil {
			progressBar.Increment(1)
			if decryptStrict {
				return fmt.Errorf("failed to construct output path for %s: %w", relPath, err)
			}
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Skipping %s: %v", relPath, err))
			}
			return nil
		}

		outDir := filepath.Dir(outPath)
		if err := fileHandler.EnsureDirectory(outDir); err != nil {
			progressBar.Increment(1)
			if decryptStrict {
				return fmt.Errorf("failed to create output directory for %s: %w", relPath, err)
			}
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Skipping %s: %v", relPath, err))
			}
			return nil
		}

		// Decrypt the file
		// #nosec G304 -- CLI validates the discovered vault path before this open.
		inputFile, err := os.Open(path)
		if err != nil {
			progressBar.Increment(1)
			if decryptStrict {
				return fmt.Errorf("failed to open %s: %w", path, err)
			}
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Skipping %s: %v", relPath, err))
			}
			return nil
		}

		header, metadata, aad, stanzas, err := fileHandler.ReadHeaderWithMetadata(inputFile)
		if err != nil {
			inputFile.Close()
			progressBar.Increment(1)
			if decryptStrict {
				return fmt.Errorf("invalid vault format for %s: %w", relPath, err)
			}
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Skipping %s: invalid format", relPath))
			}
			return nil
		}

		if header.Version != core.Version4 {
			inputFile.Close()
			progressBar.Increment(1)
			if decryptStrict {
				return fmt.Errorf("expected v4 recipient vault for %s, got v%d", relPath, header.Version)
			}
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Skipping %s: not a v4 vault", relPath))
			}
			return nil
		}

		fileKey, err := crypto.UnwrapFileKey(stanzas, identities)
		if err != nil {
			inputFile.Close()
			progressBar.Increment(1)
			if decryptStrict {
				return fmt.Errorf("no identity could decrypt %s: %w", relPath, err)
			}
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Skipping %s: no matching identity", relPath))
			}
			return nil
		}

		dataOffset, err := checkedDataOffset(header.DataOffset)
		if err != nil {
			utils.ZeroizeKey(fileKey)
			inputFile.Close()
			progressBar.Increment(1)
			if decryptStrict {
				return fmt.Errorf("invalid data offset for %s: %w", relPath, err)
			}
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Skipping %s: %v", relPath, err))
			}
			return nil
		}

		if _, err := inputFile.Seek(dataOffset, io.SeekStart); err != nil {
			utils.ZeroizeKey(fileKey)
			inputFile.Close()
			progressBar.Increment(1)
			if decryptStrict {
				return fmt.Errorf("failed to seek data in %s: %w", relPath, err)
			}
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Skipping %s: %v", relPath, err))
			}
			return nil
		}

		atomicWrite := utils.AtomicWriteFuncNoReplace
		if decryptForce {
			atomicWrite = utils.AtomicWriteFunc
		}

		writeErr := atomicWrite(outPath, 0o600, func(outputFile *os.File) error {
			defer utils.ZeroizeKey(fileKey)
			return decryptVaultToOutput(outputFile, inputFile, fileKey, header, aad, encryptionService, compressionService)
		})
		inputFile.Close()

		if writeErr != nil {
			progressBar.Increment(1)
			if decryptStrict {
				return fmt.Errorf("decryption failed for %s: %w", relPath, writeErr)
			}
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Failed to decrypt %s: %v", relPath, writeErr))
			}
			return nil
		}

		if metadata != nil {
			if err := fileHandler.WriteMetadata(outPath, metadata, decryptPreserveMode); err != nil {
				if decryptVerbose {
					PrintInfo(fmt.Sprintf("Warning: Could not restore metadata for %s: %v", relPath, err))
				}
			}
		}

		result.Succeeded++
		progressBar.Increment(1)
		if decryptVerbose {
			PrintInfo(fmt.Sprintf("[%d/%d] %s", currentFile, totalFiles, relPath))
		}

		return nil
	})

	progressBar.Wait()

	if walkErr != nil {
		PrintError(fmt.Sprintf("Directory decryption failed: %v", walkErr))
		return walkErr
	}

	result.Failed = result.Processed - result.Succeeded

	if JSONEnabled() {
		return EmitResult("decrypt", result)
	}

	if result.Failed > 0 {
		PrintInfo(fmt.Sprintf("Decrypted %d/%d files: %s -> %s", result.Succeeded, result.Processed, inputPath, outputPath))
		return fmt.Errorf("failed to decrypt %d files", result.Failed)
	}

	PrintSuccess(fmt.Sprintf("Decrypted %d files: %s -> %s", result.Succeeded, inputPath, outputPath))
	return nil
}

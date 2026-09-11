class Nokvault < Formula
  desc "Local file and directory encryption CLI"
  homepage "https://github.com/jimididit/nokvault"
  version "0.4.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jimididit/nokvault/releases/download/v0.4.1/nokvault-darwin-arm64",
          using: :nounzip
      sha256 "af4533807102ad57489d7929d73b8995a7db966a73ae1de34a18e93bca2b7c47"
    else
      url "https://github.com/jimididit/nokvault/releases/download/v0.4.1/nokvault-darwin-amd64",
          using: :nounzip
      sha256 "be2406d05fb82c3719b9806da36b42db0063c59fd862dd592aa9905395cc05c8"
    end
  end

  def install
    binary = Dir["nokvault-darwin-*"].first
    odie "NokVault release binary not found" if binary.nil?

    bin.install binary => "nokvault"
    (bin/"nokvault").chmod 0755
  end

  test do
    assert_match "v#{version}", shell_output("#{bin}/nokvault --version")
  end
end

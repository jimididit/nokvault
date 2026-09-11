class Nokvault < Formula
  desc "Local file and directory encryption CLI"
  homepage "https://github.com/jimididit/nokvault"
  version "0.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jimididit/nokvault/releases/download/v0.5.0/nokvault-darwin-arm64",
          using: :nounzip
      sha256 "55aee3751aa977670fad2b29a8603e750f21d907946112900aadfd42ddbf6153"
    else
      url "https://github.com/jimididit/nokvault/releases/download/v0.5.0/nokvault-darwin-amd64",
          using: :nounzip
      sha256 "5509277aedb1373e0178e646f16369ef8b5690d09ccc28d460d2aaaa2f30425e"
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

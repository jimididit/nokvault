class Nokvault < Formula
  desc "Local file and directory encryption CLI"
  homepage "https://github.com/jimididit/nokvault"
  version "0.3.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jimididit/nokvault/releases/download/v0.3.0/nokvault-darwin-arm64",
          using: :nounzip
      sha256 "e251e8aafb7b6d3547fba835f94309d7f7307ad6c15799e0ddc039f509957954"
    else
      url "https://github.com/jimididit/nokvault/releases/download/v0.3.0/nokvault-darwin-amd64",
          using: :nounzip
      sha256 "ea35988d789d4f050a8240a0658890edf167a2a88acfaaacba1bc78f1f429ac8"
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

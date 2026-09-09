class Nokvault < Formula
  desc "Local file and directory encryption CLI"
  homepage "https://github.com/jimididit/nokvault"
  version "0.4.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jimididit/nokvault/releases/download/v0.4.0/nokvault-darwin-arm64",
          using: :nounzip
      sha256 "1d6666bccb274053b71140bf4c19bf33b38d9ffbf699cd05a902828a6c518490"
    else
      url "https://github.com/jimididit/nokvault/releases/download/v0.4.0/nokvault-darwin-amd64",
          using: :nounzip
      sha256 "6ce741c10c670114d96a46a5e2a832e55104bee7040a4dc01b6d12009086781b"
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

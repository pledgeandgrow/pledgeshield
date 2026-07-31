class Pledgeshield < Formula
  desc "Cross-platform host security auditor for Windows, macOS, and Linux"
  homepage "https://github.com/pledgecyber/pledgeshield"
  url "https://github.com/pledgecyber/pledgeshield/archive/refs/tags/v0.1.0.tar.gz"
  sha256 ""
  license "MIT"
  version "0.1.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "PledgeShield", shell_output("#{bin}/pledgeshield --help")
  end
end

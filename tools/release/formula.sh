#!/bin/sh
# usage: formula.sh <version> <tag> <SHA256SUMS>
# Prints the Homebrew formula that installs the archives of a release.
set -eu

version=$1
tag=$2
sums=$3
base=${FILETRACE_RELEASE_URL:-https://github.com/OrlovEvgeny/filetrace/releases/download}/$tag

# archive <platform>: the url and sha256 lines of one archive.
archive()
{
    name=filetrace-$version-$1.tar.gz
    sum=$(awk -v name="$name" '$2 == name { print $1 }' "$sums")
    if [ -z "$sum" ]; then
        echo "formula.sh: $sums has no checksum for $name" >&2
        exit 1
    fi
    printf '      url "%s/%s"\n      sha256 "%s"\n' "$base" "$name" "$sum"
}

cat <<FORMULA
class Filetrace < Formula
  desc "See which files a machine sends over the network, and where they go"
  homepage "https://github.com/OrlovEvgeny/filetrace"
  version "$version"
  license "MIT"

  on_macos do
    depends_on macos: :sequoia

    on_arm do
$(archive darwin-arm64)
    end
    on_intel do
$(archive darwin-amd64)
    end
  end

  on_linux do
    on_arm do
$(archive linux-arm64)
    end
    on_intel do
$(archive linux-amd64)
    end
  end

  def install
    bin.install "bin/filetrace", "bin/filetrace-agent"
    doc.install Dir["share/doc/filetrace/*"]
  end

  def caveats
    on_macos do
      <<~EOS
        macOS has no collection backend yet: the command builds and reports
        diagnostics, and reads an agent that runs on Linux.
      EOS
    end
    on_linux do
      <<~EOS
        The agent needs root and is not registered as a service here. For a
        service that starts at boot, install the deb, rpm or apk package:
          https://github.com/OrlovEvgeny/filetrace#install
      EOS
    end
  end

  test do
    assert_match "Filetrace #{version}", shell_output("#{bin}/filetrace version")
  end
end
FORMULA

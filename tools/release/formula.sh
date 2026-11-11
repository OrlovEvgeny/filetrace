#!/bin/sh
# usage: formula.sh [--line] <version> <tag> <SHA256SUMS>
# Prints the Homebrew formula filetrace, which installs the archives of a
# release. With --line, prints the keg-only filetrace@<line> instead, which
# follows the releases of one line. FILETRACE_RELEASE_URL overrides where the
# directory of each tag is served.
set -eu

line=
if [ "${1:-}" = --line ]; then
    line=$(printf '%s\n' "${2:-}" | cut -d. -f1-2)
    shift
fi
if [ $# -ne 3 ]; then
    echo "usage: formula.sh [--line] <version> <tag> <SHA256SUMS>" >&2
    exit 2
fi

version=$1
tag=$2
sums=$3
base=${FILETRACE_RELEASE_URL:-https://filetrace.eorlov.org/dist}/$tag

class=Filetrace
keg_only=
if [ -n "$line" ]; then
    # Homebrew names the class of filetrace@26.11 FiletraceAT2611.
    class=FiletraceAT$(printf '%s\n' "$line" | tr -d .)
    keg_only='
  keg_only :versioned_formula
'
fi

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

# A failure inside the here-document below would not stop the script.
darwin_arm64=$(archive darwin-arm64)
darwin_amd64=$(archive darwin-amd64)
linux_arm64=$(archive linux-arm64)
linux_amd64=$(archive linux-amd64)

cat <<FORMULA
class $class < Formula
  desc "See which files a machine sends over the network, and where they go"
  homepage "https://github.com/OrlovEvgeny/filetrace"
  version "$version"
  license "MIT"
$keg_only
  on_macos do
    depends_on macos: :sequoia

    on_arm do
$darwin_arm64
    end
    on_intel do
$darwin_amd64
    end
  end

  on_linux do
    on_arm do
$linux_arm64
    end
    on_intel do
$linux_amd64
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

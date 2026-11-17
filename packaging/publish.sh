#!/usr/bin/env bash
# Builds the download files for one system into dist/.
#   packaging/publish.sh windows   (run on Windows, in Git Bash)
#   packaging/publish.sh macos     (run on a Mac)
#   packaging/publish.sh linux
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' Directory.Build.props)
rm -rf out dist
mkdir -p dist

pub() {
    local rid=$1; shift
    dotnet publish src/LanDrop.App -c Release -r "$rid" --self-contained true -o "out/$rid" -nologo "$@"
}

case "${1:-}" in
  windows)
    for arch in x64 arm64; do
      pub "win-$arch" -p:PublishSingleFile=true
      cp "out/win-$arch/LanDrop.exe" "dist/LanDrop-Windows-$arch.exe"
    done
    ;;
  linux)
    for arch in x64 arm64; do
      pub "linux-$arch" -p:PublishSingleFile=true
      chmod +x "out/linux-$arch/LanDrop"
      tar -C "out/linux-$arch" -czf "dist/LanDrop-Linux-$arch.tar.gz" LanDrop
    done
    ;;
  macos)
    # Icon: every size macOS wants, made from packaging/icon.png.
    iconset=out/LanDrop.iconset
    mkdir -p "$iconset"
    for s in 16 32 128 256 512; do
      sips -z $s $s packaging/icon.png --out "$iconset/icon_${s}x${s}.png" >/dev/null
      sips -z $((s * 2)) $((s * 2)) packaging/icon.png --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
    done
    iconutil -c icns "$iconset" -o out/LanDrop.icns
    for arch in arm64 x64; do
      pub "osx-$arch"
      app="out/mac-$arch/LAN Drop.app"
      mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
      cp -R "out/osx-$arch/." "$app/Contents/MacOS/"
      sed "s/__VERSION__/$version/g" packaging/macos/Info.plist > "$app/Contents/Info.plist"
      cp out/LanDrop.icns "$app/Contents/Resources/LanDrop.icns"
      # Ad-hoc signature: required for Apple Silicon. It isn't an Apple Developer ID, so
      # macOS still asks people to confirm the first time they open it.
      codesign --force --deep --sign - "$app"
      label=$([ "$arch" = arm64 ] && echo AppleSilicon || echo Intel)
      ditto -c -k --keepParent "$app" "dist/LanDrop-macOS-$label.zip"
    done
    ;;
  *)
    echo "usage: $0 windows|macos|linux" >&2
    exit 2
    ;;
esac
ls -l dist

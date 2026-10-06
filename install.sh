#!/bin/sh
# Installs encryptor (the encryptor, encrypt and decrypt commands) from its
# latest GitHub release into /usr/local/bin, using sudo if that needs it.
# Where there's no sudo, it goes in ~/.local/bin instead, for you alone.
# Linux on x64, x86, arm64 or arm, or macOS on x64 or arm64. Needs only curl
# or wget.
#
#   curl -fsSL https://raw.githubusercontent.com/neddyP/encryptor/master/install.sh | sh
#
# or download this file and run `sh install.sh`. To update, run
# `encryptor update`, which runs this script again with ENCRYPTOR_DIR set to
# the folder its copy is in. To uninstall:
#   cd /usr/local/bin && sudo rm encryptor encrypt decrypt
# or in ~/.local/bin, the same without sudo.

# All in braces, which the shell reads to the end before running any of it,
# so a download through curl | sh that gets cut off partway runs nothing.
{
  set -eu

  die() { echo "encryptor was not installed: $*" >&2; exit 1; }

  case $(uname -s) in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) die "there's no build for $(uname -s)" ;;
  esac
  case $(uname -m) in
    x86_64 | amd64) arch=x64 ;;
    i?86) arch=x86 ;;
    aarch64 | arm64) arch=arm64 ;;
    arm*) arch=arm ;;
    *) die "there's no build for $(uname -m)" ;;
  esac

  url=https://github.com/neddyP/encryptor/releases/latest/download/encryptor-$os-$arch
  dir=${ENCRYPTOR_DIR:-/usr/local/bin}
  sudo=
  if ! { mkdir -p "$dir" 2>/dev/null && [ -w "$dir" ]; }; then
    if command -v sudo >/dev/null; then
      sudo=sudo
    elif [ -z "${ENCRYPTOR_DIR:-}" ]; then
      dir=$HOME/.local/bin
    else
      die "only root can change $dir, and there's no sudo here"
    fi
  fi

  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  trap 'exit 130' HUP INT TERM
  if command -v curl >/dev/null; then
    curl -fsSL --proto '=https' "$url" >"$tmp"
  elif command -v wget >/dev/null; then
    wget -qO- "$url" >"$tmp"
  else
    die "it needs curl or wget to download it"
  fi || die "couldn't download $url"

  # Copied in under another name and renamed over the old one, so neither a
  # running encryptor nor macOS's check of its signature sees a partial file.
  $sudo mkdir -p "$dir"
  $sudo cp "$tmp" "$dir/.encryptor.new"
  $sudo chmod 755 "$dir/.encryptor.new"
  $sudo mv -f "$dir/.encryptor.new" "$dir/encryptor"
  # The binary does what it's run as.
  $sudo ln -sf encryptor "$dir/encrypt"
  $sudo ln -sf encryptor "$dir/decrypt"
  echo "encryptor installed in $dir: run encrypt, decrypt or encryptor"
  case ":$PATH:" in
    *":$dir:"*) ;;
    *)
      echo "$dir isn't on your PATH yet. Add this line to your shell's startup file"
      echo "(~/.bashrc, ~/.zshrc or ~/.profile), then open a new terminal:"
      echo "  export PATH=\"$dir:\$PATH\""
      ;;
  esac
}

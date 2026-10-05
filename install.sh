#!/usr/bin/env bash
set -e

if ! command -v curl >/dev/null || ! command -v tar >/dev/null; then
  [ "$(id -u)" = 0 ] || sudo=sudo
  if   command -v apt-get >/dev/null; then $sudo apt-get update -qq && $sudo apt-get install -y curl tar
  elif command -v dnf     >/dev/null; then $sudo dnf install -y curl tar
  elif command -v yum     >/dev/null; then $sudo yum install -y curl tar
  elif command -v pacman  >/dev/null; then $sudo pacman -Sy --noconfirm curl tar
  elif command -v apk     >/dev/null; then $sudo apk add curl tar
  elif command -v zypper  >/dev/null; then $sudo zypper install -y curl tar
  else echo "Install curl and tar, then re-run." >&2; exit 1
  fi
fi

if ! command -v npm >/dev/null; then
  os=$(uname -s | tr A-Z a-z)
  arch=$(uname -m); case $arch in x86_64) arch=x64;; aarch64) arch=arm64;; esac
  url=https://nodejs.org/dist/latest-v24.x
  file=$(curl -fsSL $url/SHASUMS256.txt | grep -o "node-v[0-9.]*-$os-$arch.tar.gz" | head -1)
  mkdir -p ~/.local/node
  curl -fsSL $url/$file | tar -xz -C ~/.local/node --strip-components=1
  export PATH=~/.local/node/bin:$PATH
  echo 'export PATH=$HOME/.local/node/bin:$PATH' | tee -a ~/.zshrc ~/.bashrc ~/.bash_profile >/dev/null
fi

npm install -g @neddyp/encryptor

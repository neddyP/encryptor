#!/bin/sh
# shellcheck disable=SC1003,SC2015,SC2016,SC2088 # literal ~, $ and \ on purpose
# Installs encryptor (the encrypt, decrypt and encryptor commands) with npm, on
# Linux or macOS, x64 or arm64. If there's no Node.js 16 or newer with npm, it
# installs Node.js first. It never uses sudo.
#
#   curl -fsSL https://raw.githubusercontent.com/neddyp/encryptor/master/install.sh | sh
#
# or download this file and run `sh install.sh`. Run it again to update.
#
# Everything goes under ~/.local (/usr/local when run as root): encryptor and,
# if it's needed, Node.js, with their commands in ~/.local/bin. If that folder
# isn't on your PATH yet, it's added in your shell's startup file.
#
# Optional settings, as environment variables:
#   ENCRYPTOR_VERSION=2.1.3      install that version instead of the latest
#   ENCRYPTOR_PREFIX=~/tools     install under that folder instead of ~/.local
#   ENCRYPTOR_NO_MODIFY_PATH=1   never edit a shell startup file
#   NODEJS_ORG_MIRROR=URL        get Node.js from a mirror of nodejs.org/dist
# for example:  curl -fsSL .../install.sh | ENCRYPTOR_VERSION=2.1.3 sh
#
# Everything runs from main, called on the last line, so a download that gets
# cut off partway runs nothing.

set -eu

PACKAGE=@neddyp/encryptor
NODE_MIN=16
# Node.js release lines to try, newest first. Older machines that can't run a
# newer one (an older macOS, say) fall back to the next.
NODE_LINES="24 22 20"
# Builds for musl (Alpine) and old glibc, which nodejs.org doesn't make.
NODE_UNOFFICIAL=https://unofficial-builds.nodejs.org/download/release
NODE_UNOFFICIAL_LINES="24 22"

say() { printf '%s\n' "$*"; }
warn() { printf '\nWarning: %s\n' "$*" >&2; }
die() {
  printf '\nencryptor was not installed: %s\n' "$*" >&2
  exit 1
}
has() { command -v "$1" >/dev/null 2>&1; }

# Shows a path with the home folder as ~.
pretty() {
  if [ -n "$home" ]; then
    case $1 in
      "$home") printf '~' && return 0 ;;
      "$home"/*) printf '~/%s' "${1#"$home"/}" && return 0 ;;
    esac
  fi
  printf '%s' "$1"
}

on_path() {
  case ":${PATH:-}:" in
    *":$1:"* | *":$1/:"*) return 0 ;;
  esac
  return 1
}

# Sets os, arch and os_name for this machine, or stops if there's no build.
detect_platform() {
  kernel=$(uname -s 2>/dev/null || true)
  machine=$(uname -m 2>/dev/null || true)
  case $kernel in
    Linux) os=linux os_name=Linux ;;
    Darwin) os=darwin os_name=macOS ;;
    *) die "it runs on Linux and macOS only, not ${kernel:-this system}." ;;
  esac
  case $machine in
    x86_64 | amd64) arch=x64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "there's no build for $os_name on ${machine:-this processor}, only for x64 and arm64. To build it yourself, see https://github.com/neddyp/encryptor#from-source" ;;
  esac
  # A terminal running under Rosetta reports x86_64 on Apple Silicon. Use the
  # native builds there.
  if [ "$os" = darwin ] && [ "$arch" = x64 ] &&
    [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
    arch=arm64
  fi
}

# Downloads URL to FILE with curl, or with wget if curl is missing or fails.
# The shell writes the file, not the downloader, because some sandboxed curls
# (Ubuntu's snap) can't write outside the home folder.
fetch() {
  if has curl &&
    curl --fail --silent --show-error --location --retry 2 \
      --connect-timeout 30 "$1" >"$2" 2>"$tmp/fetch.log"; then
    return 0
  fi
  if has wget && wget -q -O - "$1" >"$2" 2>>"$tmp/fetch.log"; then
    return 0
  fi
  return 1
}

# Prints the SHA-BITS hash of FILE in hex, with whichever tool this system has.
sha_hex() {
  if has "sha$1sum"; then
    "sha$1sum" "$2" | awk '{ print $1 }'
  elif has shasum; then
    shasum -a "$1" "$2" | awk '{ print $1 }'
  elif has openssl; then
    openssl dgst "-sha$1" <"$2" | awk '{ print $NF }'
  fi
}

# Prints the major version of the node at PATH, or nothing if it won't run.
node_major() {
  v=$("$1" --version </dev/null 2>/dev/null) || return 0
  v=${v#v}
  v=${v%%.*}
  case $v in
    '' | *[!0-9]*) ;;
    *) printf '%s' "$v" ;;
  esac
}

# Succeeds if NODE is Node.js 16 or newer with a working npm beside it (or
# anywhere on PATH), and sets node_bin and npm_bin to them.
usable_node() {
  if [ -z "$1" ] || [ ! -f "$1" ] || [ ! -x "$1" ]; then return 1; fi
  major=$(node_major "$1")
  if [ -z "$major" ] || [ "$major" -lt "$NODE_MIN" ]; then return 1; fi
  npm_try=$(dirname "$1")/npm
  if [ ! -x "$npm_try" ]; then npm_try=$(command -v npm 2>/dev/null || true); fi
  if [ -z "$npm_try" ]; then return 1; fi
  PATH=$(dirname "$1"):$PATH "$npm_try" --version </dev/null >/dev/null 2>&1 ||
    return 1
  node_bin=$1
  npm_bin=$npm_try
}

# Finds a Node.js to use. One already in the prefix must work, because it
# comes first on PATH and so is the one encryptor will run with.
find_node() {
  if [ -e "$prefix/bin/node" ]; then
    if usable_node "$prefix/bin/node"; then return 0; fi
    return 1
  fi
  if usable_node "$(command -v node 2>/dev/null || true)"; then return 0; fi
  return 1
}

is_musl() {
  for f in /lib/ld-musl-*.so.1; do
    if [ -e "$f" ]; then return 0; fi
  done
  ldd --version 2>&1 | grep -qi musl
}

# Succeeds if glibc is older than 2.28, too old for nodejs.org's Linux builds.
old_glibc() {
  v=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{ print $2 }') || return 1
  case $v in
    2.[0-9] | 2.[0-9].* | 2.1[0-9] | 2.1[0-9].* | 2.2[0-7] | 2.2[0-7].*) return 0 ;;
  esac
  return 1
}

# Downloads the Node.js build for PLATFORM (like linux-x64) that BASE_URL's
# SHASUMS256.txt lists, checks it, unpacks it and makes sure it runs here.
# Sets node_src and node_version, or node_problem when it fails.
try_node_build() {
  if ! fetch "$1/SHASUMS256.txt" "$tmp/SHASUMS256.txt"; then
    node_problem="couldn't download $1/SHASUMS256.txt: $(cat "$tmp/fetch.log")"
    return 1
  fi
  file=$(awk -v p="$2" '$2 ~ ("^node-v[0-9.]+-" p "[.]tar[.]gz$") { print $2; exit }' \
    "$tmp/SHASUMS256.txt")
  if [ -z "$file" ]; then
    node_problem="$1 has no $2 build"
    return 1
  fi
  want=$(awk -v f="$file" '$2 == f { print $1; exit }' "$tmp/SHASUMS256.txt")
  node_version=${file#node-}
  node_version=${node_version%%-*}

  say "Downloading Node.js $node_version..."
  if ! fetch "$1/$file" "$tmp/$file"; then
    node_problem="couldn't download $1/$file: $(cat "$tmp/fetch.log")"
    return 1
  fi
  got=$(sha_hex 256 "$tmp/$file")
  [ -n "$got" ] ||
    die "the Node.js download can't be checked: there's no SHA-256 tool (looked for sha256sum, shasum and openssl)."
  [ "$got" = "$want" ] ||
    die "the Node.js download doesn't match its published checksum, so it wasn't used. Try again. If it keeps happening, something on your network is changing downloads."

  rm -rf "$tmp/node"
  mkdir "$tmp/node"
  if ! tar -xzf "$tmp/$file" -C "$tmp/node" 2>"$tmp/tar.log"; then
    node_problem="couldn't unpack $file: $(cat "$tmp/tar.log")"
    rm -f "$tmp/$file"
    return 1
  fi
  rm -f "$tmp/$file"
  node_src=$tmp/node/${file%.tar.gz}
  if ! out=$("$node_src/bin/node" --version </dev/null 2>&1); then
    node_problem="Node.js $node_version doesn't run on this system: $out"
    say "Node.js $node_version doesn't run on this system."
    return 1
  fi
}

# Sets unofficial_version to the newest unofficial Node.js MAJOR release that
# has a PLATFORM build.
find_unofficial() {
  if [ ! -s "$tmp/index.tab" ] &&
    ! fetch "$NODE_UNOFFICIAL/index.tab" "$tmp/index.tab"; then
    node_problem="couldn't download $NODE_UNOFFICIAL/index.tab: $(cat "$tmp/fetch.log")"
    return 1
  fi
  unofficial_version=$(awk -F "$(printf '\t')" -v m="v$1." -v f="$2" \
    'index($1, m) == 1 && index("," $3 ",", "," f ",") { print $1; exit }' \
    "$tmp/index.tab")
  if [ -z "$unofficial_version" ]; then
    node_problem="there's no $2 build of Node.js $1"
    return 1
  fi
}

# Copies the unpacked Node.js at node_src into the prefix, replacing any old
# one there.
place_node() {
  rm -rf "$prefix/lib/node_modules/npm" "$prefix/lib/node_modules/corepack" \
    "$prefix/include/node"
  rm -f "$prefix/bin/node" "$prefix/bin/npm" "$prefix/bin/npx" \
    "$prefix/bin/corepack"
  for d in bin include lib share; do
    if [ -d "$node_src/$d" ]; then
      { mkdir -p "$prefix/$d" && cp -RP "$node_src/$d/." "$prefix/$d/"; } ||
        die "couldn't copy Node.js into $(pretty "$prefix/$d")."
    fi
  done
  rm -rf "$tmp/node"
  usable_node "$prefix/bin/node" ||
    die "Node.js $node_version was copied into $(pretty "$prefix") but doesn't work there."
  say "Installed Node.js $node_version in $(pretty "$prefix")."
}

# Puts a working Node.js and npm in place, setting node_bin and npm_bin.
install_node() {
  node_problem=
  if [ "$os" = linux ] && is_musl; then
    if [ "$(id -u)" = 0 ] && has apk; then
      say "Installing Node.js with apk..."
      if apk add --no-cache nodejs npm &&
        usable_node "$(command -v node 2>/dev/null || true)"; then
        return 0
      fi
    fi
    say "Installing Node.js into $(pretty "$prefix")..."
    for major in $NODE_UNOFFICIAL_LINES; do
      if find_unofficial "$major" "linux-$arch-musl" &&
        try_node_build "$NODE_UNOFFICIAL/$unofficial_version" "linux-$arch-musl"; then
        place_node
        return 0
      fi
    done
  elif [ "$os" = linux ] && old_glibc; then
    say "Installing Node.js into $(pretty "$prefix")..."
    if [ "$arch" = x64 ]; then
      for major in $NODE_UNOFFICIAL_LINES; do
        if find_unofficial "$major" linux-x64-glibc-217 &&
          try_node_build "$NODE_UNOFFICIAL/$unofficial_version" linux-x64-glibc-217; then
          place_node
          return 0
        fi
      done
    else
      node_problem="this system's C library (glibc $(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{ print $2 }')) is too old for Node.js's arm64 builds"
    fi
  else
    say "Installing Node.js into $(pretty "$prefix")..."
    mirror=${NODEJS_ORG_MIRROR:-https://nodejs.org/dist}
    mirror=${mirror%/}
    for major in $NODE_LINES; do
      if try_node_build "$mirror/latest-v$major.x" "$os-$arch"; then
        place_node
        return 0
      fi
    done
  fi
  die "couldn't install Node.js: $node_problem
Install Node.js $NODE_MIN or newer yourself, from https://nodejs.org or with your system's package manager, then run this again."
}

# Prints any encrypt, decrypt or encryptor on PATH before DIR, which would
# run instead of the ones in DIR.
shadowing() {
  printf '%s\n' "${PATH:-}" | tr ':' '\n' | {
    while IFS= read -r entry; do
      entry=${entry%/}
      if [ "$entry" = "$1" ]; then break; fi
      if [ -z "$entry" ]; then continue; fi
      for name in encryptor encrypt decrypt; do
        if [ -f "$entry/$name" ] && [ -x "$entry/$name" ]; then
          printf '%s\n' "$entry/$name"
        fi
      done
    done
    true
  }
}

# Makes new terminals find DIR, adding it to the login shell's startup file if
# it isn't on PATH. Sets next_step to what the user should do now.
setup_path() {
  dir=$1
  manual="add this line to your shell's startup file (such as ~/.zshrc or ~/.bashrc), then open a new terminal:
  export PATH=\"$dir:\$PATH\""
  next_step=manual

  if on_path "$dir"; then
    next_step=
    return 0
  fi
  case ${ENCRYPTOR_NO_MODIFY_PATH:-} in
    '' | 0 | false | no) ;;
    *)
      say "$(pretty "$dir") isn't on your PATH. To use encryptor, $manual"
      return 0
      ;;
  esac
  # Startup files are shell code, so odd folder names are left to the user.
  case $dir in
    *'"'* | *'\'* | *'$'* | *'`'*)
      say "$(pretty "$dir") isn't on your PATH. To use encryptor, $manual"
      return 0
      ;;
  esac
  if [ -z "$home" ]; then
    say "$(pretty "$dir") isn't on your PATH. To use encryptor, $manual"
    return 0
  fi

  rc_dir=$dir
  case $dir in
    "$home"/*) rc_dir='$HOME'/${dir#"$home"/} ;;
  esac
  line="export PATH=\"$rc_dir:\$PATH\""
  reload=source
  case $(basename "${SHELL:-sh}") in
    zsh) rc=${ZDOTDIR:-$home}/.zshrc ;;
    bash)
      # Linux terminals start bash as an interactive shell, which reads
      # ~/.bashrc. macOS's Terminal starts a login shell, which reads only the
      # first of these that exists.
      if [ "$os" = linux ]; then
        rc=$home/.bashrc
      elif [ -f "$home/.bash_profile" ]; then
        rc=$home/.bash_profile
      elif [ -f "$home/.bash_login" ]; then
        rc=$home/.bash_login
      elif [ -f "$home/.profile" ]; then
        rc=$home/.profile
      else
        rc=$home/.bash_profile
      fi
      ;;
    fish)
      rc=${XDG_CONFIG_HOME:-$home/.config}/fish/conf.d/encryptor.fish
      line="contains -- \"$rc_dir\" \$PATH; or set -gx PATH \"$rc_dir\" \$PATH"
      ;;
    csh | tcsh)
      if [ -f "$home/.tcshrc" ]; then rc=$home/.tcshrc; else rc=$home/.cshrc; fi
      line="setenv PATH \"$rc_dir:\$PATH\""
      ;;
    *)
      rc=$home/.profile
      reload=.
      ;;
  esac

  if grep -qsF -e "$rc_dir" -e "$dir" "$rc" 2>/dev/null; then
    say "$(pretty "$rc") already adds $(pretty "$dir") to your PATH."
  elif mkdir -p "$(dirname "$rc")" 2>/dev/null &&
    printf '\n# Added by the encryptor installer\n%s\n' "$line" >>"$rc" 2>/dev/null; then
    say "Added $(pretty "$dir") to your PATH in $(pretty "$rc")."
  else
    say "Couldn't edit $(pretty "$rc"). To use encryptor, $manual"
    return 0
  fi
  next_step="Open a new terminal window (or run: $reload $(pretty "$rc")), then try:"
}

cleanup() {
  if [ -n "${tmp:-}" ]; then rm -rf "$tmp"; fi
}

main() {
  # Run as plain sh even if started with zsh.
  if [ -n "${ZSH_VERSION:-}" ]; then emulate -L sh; fi

  home=${HOME:-}
  home=${home%/}
  tmp=
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  detect_platform

  if [ -n "${ENCRYPTOR_PREFIX:-}" ]; then
    prefix=$ENCRYPTOR_PREFIX
    case $prefix in
      '~') prefix=$home ;;
      '~/'*) prefix=$home/${prefix#'~/'} ;;
    esac
    case $prefix in
      /*) ;;
      *) prefix=$(pwd)/$prefix ;;
    esac
  elif [ "$(id -u)" = 0 ]; then
    prefix=/usr/local
  elif [ -n "$home" ]; then
    prefix=$home/.local
  else
    die "HOME isn't set, so there's no home folder to install into. Set ENCRYPTOR_PREFIX to a folder you own and run this again."
  fi
  while [ "$prefix" != / ] && [ "${prefix%/}" != "$prefix" ]; do
    prefix=${prefix%/}
  done
  bin=$prefix/bin

  for d in "$prefix" "$prefix/bin" "$prefix/lib"; do
    if ! mkdir -p "$d" 2>/dev/null || [ ! -w "$d" ]; then
      if [ "$(id -u)" != 0 ] && [ -e "$d" ]; then
        die "you don't have permission to write to $(pretty "$d"). If an earlier sudo command created it, give it back to yourself with:
  sudo chown -R \"\$(id -un)\" \"$d\"
then run this again."
      fi
      die "you don't have permission to write to $(pretty "$d"). Choose a folder you own with ENCRYPTOR_PREFIX, or run this as root."
    fi
  done

  if ! has curl && ! has wget; then
    die "downloading needs curl or wget, and this system has neither. Install curl (for example 'sudo apt install curl', 'sudo dnf install curl' or 'sudo apk add curl') and run this again."
  fi

  # Work inside the prefix rather than /tmp, which may be too small for
  # Node.js or not allow running programs.
  tmp=$(mktemp -d "$prefix/.encryptor-install.XXXXXX" 2>/dev/null) || tmp=
  if [ -z "$tmp" ]; then
    tmp=$prefix/.encryptor-install.$$
    mkdir -m 700 "$tmp" 2>/dev/null ||
      die "couldn't create a temporary folder in $(pretty "$prefix")."
  fi

  say "Installing encryptor for $os_name ($arch) under $(pretty "$prefix")"

  if find_node; then
    say "Using Node.js $("$node_bin" --version) at $(pretty "$node_bin")."
  else
    if [ -e "$prefix/bin/node" ]; then
      say "The Node.js in $(pretty "$bin") is older than $NODE_MIN or doesn't work, so it will be replaced."
    else
      say "No Node.js $NODE_MIN or newer with npm was found."
    fi
    install_node
  fi
  node_dir=$(dirname "$node_bin")

  wanted=${ENCRYPTOR_VERSION:-latest}
  wanted=${wanted#v}
  spec=$PACKAGE@$wanted
  say "Installing $spec with npm..."
  # A fresh npm cache sidesteps a ~/.npm left owned by root by an earlier
  # sudo npm, a common cause of EACCES errors.
  if ! PATH=$node_dir:$PATH "$npm_bin" install --global --prefix "$prefix" \
    --cache "$tmp/npm-cache" --ignore-scripts --no-audit --no-fund \
    --no-update-notifier --loglevel=error "$spec" </dev/null; then
    # npm's log is in the temporary folder, which is about to be removed.
    log=
    for f in "$tmp"/npm-cache/_logs/*.log; do
      if [ -f "$f" ]; then log=$f; fi
    done
    if [ -n "$log" ] && cp "$log" "${TMPDIR:-/tmp}/encryptor-npm.log" 2>/dev/null; then
      log=" npm's full log is in ${TMPDIR:-/tmp}/encryptor-npm.log."
    else
      log=
    fi
    die "npm couldn't install $spec (its message is above).$log Check your internet connection and that the version exists, then run this again."
  fi

  check=$(PATH=$node_dir:$PATH "$bin/encryptor" --version </dev/null 2>&1) &&
    code=0 || code=$?
  if [ "$code" -ne 0 ]; then
    die "it was installed but doesn't run: ${check:-exit status $code}"
  fi
  version=$(printf '%s\n' "$check" | awk 'NR == 1 { v = $2; sub(/,$/, "", v); print v }')

  say ""
  say "Installed encryptor $version in $(pretty "$bin")."
  setup_path "$bin"

  # In new terminals bin comes first on PATH, unless it was already on it.
  if on_path "$bin"; then run_path=$PATH; else run_path=$bin:${PATH:-}; fi
  run_node=$(PATH=$run_path && command -v node 2>/dev/null || true)
  run_major=
  if [ -n "$run_node" ]; then run_major=$(node_major "$run_node"); fi
  if [ -z "$run_major" ] || [ "$run_major" -lt "$NODE_MIN" ]; then
    warn "encryptor needs Node.js $NODE_MIN or newer, but in new terminals 'node' will be ${run_node:-missing}${run_major:+ (version $run_major)}. Put $(pretty "$node_dir") before it on your PATH."
  fi
  first=$(PATH=$run_path && shadowing "$bin" | head -n 1)
  if [ -n "$first" ]; then
    warn "$first comes earlier on your PATH, so it runs instead of this one. If it's from an older npm install, remove it with: npm uninstall -g $PACKAGE"
  fi

  case $next_step in
    manual) ;;
    '') say "" && say "Run this to get started:" && say "  encryptor --help" ;;
    *) say "" && say "$next_step" && say "  encryptor --help" ;;
  esac
  say ""
  say "To update encryptor later, run this installer again."
}

main "$@"

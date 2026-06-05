#!/usr/bin/env bash
# AIGitsploit / GitVulture — Universal Installer for Linux & macOS
# Just double-click this file or run:  bash install.sh
set -u

# ───────── colour helpers ─────────
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED='';GREEN='';YELLOW='';CYAN='';BOLD='';NC=''
fi

banner() {
cat <<'EOF'
   ___   _____ _____ _ _   ___       _       _ _
  / _ \ |_   _/ ____(_) | / __|     | |     (_) |
 | |_| |  | || |  __ _| |_\__ \_ __ | | ___  _| |_
 |  _  |  | || | |_ | | __|__) | '_ \| |/ _ \| | __|
 | | | | _| || |__| | | |_/ ___ /| |_) | | (_) | | |_
 \_| |_/_____\_____|_|\__|\____/ | .__/|_|\___/|_|\__|
                                 |_|
   AI-driven .git exposure exploitation framework
   Universal installer  ·  Linux / macOS / WSL
EOF
}

ok()    { printf " ${GREEN}✔${NC} %s\n" "$*"; }
info()  { printf " ${CYAN}ℹ${NC} %s\n" "$*"; }
warn()  { printf " ${YELLOW}⚠${NC} %s\n" "$*"; }
err()   { printf " ${RED}✘${NC} %s\n" "$*"; }
step()  { printf "\n${BOLD}${CYAN}━━ %s ━━${NC}\n" "$*"; }
die()   { err "$*"; press_to_exit 1; }

press_to_exit() {
    local code=${1:-0}
    # When launched by a file manager (double-click), keep the window open
    if [ -t 0 ] && { [ -n "${LAUNCHED_FROM_FILE_MANAGER:-}" ] || \
       [ "${TERM_PROGRAM:-}" = "Apple_Terminal" ]; }; then
        echo; read -rp "Press Enter to close…" _ || true
    fi
    exit "$code"
}

trap 'err "Aborted (line $LINENO)."; press_to_exit 1' ERR
set -e

# ───────── configuration ─────────
REPO_URL="${AIGITSPLOIT_REPO:-https://github.com/sinoolamoo-lgtm/AIGitsploit.git}"
INSTALL_DIR="${AIGITSPLOIT_HOME:-$HOME/AIGitsploit}"
DEFAULT_LLM_KEY="${EMERGENT_LLM_KEY:-sk-emergent-07c12D71306386c4d9}"
LLM_ENV_FILE="$HOME/.gitvulture.env"
PY_MIN="3.10"
EMERGENT_INDEX="https://d33sy5i8bnduwe.cloudfront.net/simple/"

clear 2>/dev/null || true
printf "${GREEN}"; banner; printf "${NC}\n"

# ───────── 1. detect OS / package manager ─────────
step "1/8 Detecting your operating system"
OS_NAME="unknown"; PKG=""; UPDATE_CMD=""; SUDO=""
if [ "$(uname -s)" = "Darwin" ]; then
    OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null)"
    if ! command -v brew >/dev/null 2>&1; then
        info "Homebrew not found — will install it now (may prompt for password)"
        NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
            || die "Homebrew install failed. Visit https://brew.sh"
        # Add brew to current PATH (M1 / Intel)
        for p in /opt/homebrew/bin /usr/local/bin; do
            [ -x "$p/brew" ] && eval "$($p/brew shellenv)"
        done
    fi
    PKG="brew install"
elif [ -f /etc/debian_version ]; then
    OS_NAME="$(lsb_release -ds 2>/dev/null || cat /etc/debian_version)"
    [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    PKG="$SUDO apt-get install -y"
    UPDATE_CMD="$SUDO apt-get update -y"
elif [ -f /etc/arch-release ]; then
    OS_NAME="Arch Linux"
    [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    PKG="$SUDO pacman -S --noconfirm --needed"
elif [ -f /etc/fedora-release ]; then
    OS_NAME="Fedora $(rpm -E %fedora)"
    [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    PKG="$SUDO dnf install -y"
elif [ -f /etc/redhat-release ]; then
    OS_NAME="$(cat /etc/redhat-release)"
    [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    PKG="$SUDO yum install -y"
elif command -v zypper >/dev/null 2>&1; then
    OS_NAME="openSUSE"
    [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    PKG="$SUDO zypper install -y"
elif command -v apk >/dev/null 2>&1; then
    OS_NAME="Alpine"
    [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    PKG="$SUDO apk add --no-cache"
else
    warn "Unknown Linux distro — will try the generic flow"
fi
ok "Detected: $OS_NAME"

# Pre-update package index where appropriate
[ -n "$UPDATE_CMD" ] && $UPDATE_CMD >/dev/null 2>&1 || true

install_pkg() {
    local what="$1"
    if [ -z "$PKG" ]; then
        warn "No package manager available — install '$what' manually."
        return 1
    fi
    $PKG "$what" 2>/dev/null || warn "$what install returned non-zero"
}

# ───────── 2. ensure git, python3, pip, venv, openssl ─────────
step "2/8 Checking core tools (git, python3 ≥ $PY_MIN, pip, venv)"
need=""
command -v git >/dev/null 2>&1 || need="$need git"
command -v python3 >/dev/null 2>&1 || need="$need python3"
command -v pip3 >/dev/null 2>&1 || need="$need python3-pip"
python3 -c "import venv" >/dev/null 2>&1 || need="$need python3-venv"
command -v openssl >/dev/null 2>&1 || need="$need openssl"
command -v curl >/dev/null 2>&1 || need="$need curl"

if [ -n "$need" ]; then
    info "Installing missing packages:$need"
    for pkg in $need; do install_pkg "$pkg" || true; done
fi

command -v git     >/dev/null 2>&1 || die "git is still missing — please install it."
command -v python3 >/dev/null 2>&1 || die "python3 is still missing — please install it."
ok "git $(git --version | awk '{print $3}')"
ok "$(python3 --version 2>&1)"

# Python version check
if ! python3 - <<'PY'
import sys
sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY
then
    die "Python 3.10+ required (found $(python3 --version))"
fi
ok "Python version OK"

# ───────── 3. clone / update repository ─────────
step "3/8 Fetching AIGitsploit"
if [ -d "$INSTALL_DIR/.git" ]; then
    info "Repo already at $INSTALL_DIR — pulling latest changes"
    git -C "$INSTALL_DIR" pull --ff-only || warn "git pull failed; using existing copy"
else
    if [ -e "$INSTALL_DIR" ]; then
        bak="${INSTALL_DIR}.bak.$(date +%s)"
        warn "$INSTALL_DIR exists but is not a git repo — moving aside to $bak"
        mv "$INSTALL_DIR" "$bak"
    fi
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" || die "git clone failed"
fi
ok "Source at $INSTALL_DIR"

# ───────── 4. virtualenv ─────────
step "4/8 Creating an isolated Python virtualenv"
VENV="$INSTALL_DIR/.venv"
[ -d "$VENV" ] || python3 -m venv "$VENV"
# shellcheck disable=SC1091
. "$VENV/bin/activate"
ok "venv ready: $VENV"

# ───────── 5. install Python deps ─────────
step "5/8 Installing GitVulture (this takes 1–3 minutes)"
pip install --quiet -U pip wheel setuptools
info "Fetching emergentintegrations from Emergent's private index…"
pip install --quiet --extra-index-url "$EMERGENT_INDEX" "emergentintegrations==0.2.0" \
    || die "pip install emergentintegrations failed"
info "Installing GitVulture itself…"
( cd "$INSTALL_DIR" && pip install --quiet --extra-index-url "$EMERGENT_INDEX" -e . ) \
    || die "pip install -e . failed"
ok "GitVulture package installed"

# ───────── 6. write LLM key ─────────
step "6/8 Configuring Emergent LLM key"
mkdir -p "$(dirname "$LLM_ENV_FILE")"
cat > "$LLM_ENV_FILE" <<EOF
EMERGENT_LLM_KEY=$DEFAULT_LLM_KEY
EOF
chmod 600 "$LLM_ENV_FILE"
ok "LLM key written to $LLM_ENV_FILE (mode 600)"

# ───────── 7. shell alias / launcher ─────────
step "7/8 Adding 'gitvulture' to your shell"
LAUNCHER="$VENV/bin/gitvulture"
add_alias() {
    local rc="$1"
    [ -f "$rc" ] || return
    if ! grep -q "AIGitsploit-alias" "$rc" 2>/dev/null; then
        {
            echo ""
            echo "# AIGitsploit-alias (added by install.sh)"
            echo "alias gitvulture='$LAUNCHER'"
        } >> "$rc"
        info "Updated $rc"
    fi
}
add_alias "$HOME/.bashrc"
add_alias "$HOME/.zshrc"
add_alias "$HOME/.profile"
ok "Alias added — restart your terminal or run 'source ~/.bashrc'"

# Also copy a thin launcher into /usr/local/bin if writable
if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    cat > /usr/local/bin/gitvulture <<EOF
#!/usr/bin/env bash
exec "$LAUNCHER" "\$@"
EOF
    chmod +x /usr/local/bin/gitvulture
    ok "Symlink installed at /usr/local/bin/gitvulture"
fi

# ───────── 8. smoke test ─────────
step "8/8 Verifying installation"
"$LAUNCHER" --help >/dev/null 2>&1 || die "Smoke test failed"
ok "'gitvulture --help' works"

# ───────── done ─────────
echo
printf "${GREEN}═══════════════════════════════════════════════════════════════${NC}\n"
printf "${GREEN}  ✓  INSTALLATION COMPLETE${NC}\n"
printf "${GREEN}═══════════════════════════════════════════════════════════════${NC}\n"
cat <<EOF

  ${BOLD}Quick tests${NC}
    gitvulture --help
    gitvulture --list-targets
    gitvulture https://my-lab.example.com --ai --escalate --insecure

  ${BOLD}Storage layout (sqlmap-style)${NC}
    ~/.gitvulture/output/<host>/<UTC-timestamp>/

  ${BOLD}Installed paths${NC}
    Source code    $INSTALL_DIR
    Virtualenv     $VENV
    LLM key        $LLM_ENV_FILE
    CLI binary     $LAUNCHER

  ${BOLD}Update later${NC}
    cd $INSTALL_DIR && git pull && . .venv/bin/activate && pip install -e .

  ${YELLOW}Reminder:${NC} use only on assets you own or are authorised to test.

EOF
press_to_exit 0

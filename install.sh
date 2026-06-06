#!/usr/bin/env bash
# GitVulture installer for Linux / macOS / WSL
# Usage:
#   ./install.sh                  # interactive
#   ./install.sh --quiet          # skip prompts, use defaults
#   ./install.sh --venv ~/.gv     # custom venv path

set -e
GV_VENV="${GV_VENV:-$HOME/.gitvulture/venv}"
GV_BIN="${GV_BIN:-$HOME/.local/bin}"
QUIET=0
for a in "$@"; do
    case "$a" in
        --quiet|-q)  QUIET=1 ;;
        --venv=*)    GV_VENV="${a#*=}" ;;
        --bin=*)     GV_BIN="${a#*=}" ;;
        --help)
            cat <<EOF
GitVulture installer — Linux / macOS

Options:
  --quiet              run non-interactively
  --venv=PATH          custom venv path (default: ~/.gitvulture/venv)
  --bin=PATH           where to drop the 'gitvulture' shim (default: ~/.local/bin)
EOF
            exit 0 ;;
    esac
done

GREEN='\033[1;32m'; YELLOW='\033[1;33m'; RED='\033[1;31m'; CYAN='\033[1;36m'; NC='\033[0m'
say()   { echo -e "${CYAN}[gitvulture]${NC} $*"; }
ok()    { echo -e "${GREEN}[ ok ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC} $*"; }
fail()  { echo -e "${RED}[fail]${NC} $*" 1>&2; exit 1; }

# ---------- 1. Pre-flight ----------
say "checking prerequisites..."
command -v python3 >/dev/null 2>&1 || fail "python3 not found. Install Python 3.10+ first."
PY_VER=$(python3 -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
PY_MAJOR=${PY_VER%.*}; PY_MINOR=${PY_VER#*.}
[ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ] || fail "Python 3.10+ required (found $PY_VER)"
ok "python $PY_VER"

command -v git  >/dev/null 2>&1 || warn "git not found (only required if you want to clone fresh)"
command -v curl >/dev/null 2>&1 || fail "curl not found"

# ---------- 2. venv ----------
mkdir -p "$(dirname "$GV_VENV")"
if [ ! -d "$GV_VENV" ]; then
    say "creating venv at $GV_VENV"
    python3 -m venv "$GV_VENV"
fi
# shellcheck disable=SC1091
source "$GV_VENV/bin/activate"
pip install --upgrade pip setuptools wheel >/dev/null 2>&1
ok "venv ready"

# ---------- 3. Install package ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say "installing gitvulture from $SCRIPT_DIR"
pip install --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/ \
            -e "$SCRIPT_DIR" >/dev/null 2>&1 || \
    pip install -e "$SCRIPT_DIR" >/dev/null 2>&1 || fail "pip install failed"
ok "gitvulture installed (editable)"

# ---------- 4. Embed EMERGENT_LLM_KEY ----------
DEFAULT_KEY="sk-emergent-07c12D71306386c4d9"
CFG_DIR="$HOME/.gitvulture"
CFG_FILE="$CFG_DIR/config.env"
mkdir -p "$CFG_DIR"

if [ -f "$CFG_FILE" ] && grep -q EMERGENT_LLM_KEY "$CFG_FILE"; then
    ok "existing config found at $CFG_FILE — leaving in place"
else
    if [ "$QUIET" -eq 1 ]; then
        KEY="$DEFAULT_KEY"
    else
        echo
        echo -e "${YELLOW}EMERGENT LLM KEY${NC} (universal key for Claude/Gemini/OpenAI)"
        echo "Press ENTER to use the bundled default key, or paste your own."
        printf "key [%s]: " "$DEFAULT_KEY"
        read -r USER_KEY || true
        KEY="${USER_KEY:-$DEFAULT_KEY}"
    fi
    cat > "$CFG_FILE" <<EOF
# GitVulture configuration — sourced automatically by the CLI on every run.
EMERGENT_LLM_KEY=$KEY
EOF
    chmod 600 "$CFG_FILE"
    ok "wrote $CFG_FILE (chmod 600)"
fi

# ---------- 5. Drop a wrapper into ~/.local/bin ----------
mkdir -p "$GV_BIN"
cat > "$GV_BIN/gitvulture" <<EOF
#!/usr/bin/env bash
# GitVulture launcher — sources config.env then invokes the venv'd CLI
set -a
[ -f "$CFG_FILE" ] && . "$CFG_FILE"
set +a
exec "$GV_VENV/bin/python" -m gitvulture.cli "\$@"
EOF
chmod +x "$GV_BIN/gitvulture"
ok "installed launcher at $GV_BIN/gitvulture"

# ---------- 6. PATH hint ----------
case ":$PATH:" in
    *":$GV_BIN:"*) ;;
    *)
        warn "$GV_BIN is NOT on your PATH"
        echo "  add this to ~/.bashrc, ~/.zshrc, or equivalent:"
        echo "    export PATH=\"$GV_BIN:\$PATH\""
        ;;
esac

# ---------- 7. Smoke test ----------
say "smoke test..."
if "$GV_BIN/gitvulture" --help >/dev/null 2>&1; then
    ok "gitvulture --help passes"
else
    fail "smoke test failed — please report"
fi

# ---------- 8. Done ----------
echo
echo -e "${GREEN}gitvulture installed.${NC}"
echo "  binary:   $GV_BIN/gitvulture"
echo "  config:   $CFG_FILE"
echo "  venv:     $GV_VENV"
echo
echo "  Try:  ${CYAN}gitvulture --help${NC}"
echo "        ${CYAN}gitvulture --interactive${NC}"
echo "        ${CYAN}gitvulture https://target.tld/ --insecure --i-have-permission${NC}"

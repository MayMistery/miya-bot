#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════
#  Miya — One-click Install / Update
# ═══════════════════════════════════════════════════════════════
#
#  Install:
#    curl -fsSL https://raw.githubusercontent.com/MayMistery/miya-bot/main/install.sh | bash
#
#  Update (from inside repo):
#    ./install.sh update
#
# ═══════════════════════════════════════════════════════════════

REPO="https://github.com/MayMistery/miya-bot.git"
INSTALL_DIR="${MIYA_DIR:-$HOME/miya-bot}"
BRANCH="${MIYA_BRANCH:-main}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[miya]${NC} $*"; }
ok()    { echo -e "${GREEN}[miya]${NC} $*"; }
warn()  { echo -e "${YELLOW}[miya]${NC} $*"; }
err()   { echo -e "${RED}[miya]${NC} $*" >&2; }

banner() {
    echo -e "${RED}${BOLD}"
    echo "  ███╗   ███╗ ██╗ ██╗   ██╗  █████╗"
    echo "  ████╗ ████║ ██║ ╚██╗ ██╔╝ ██╔══██╗"
    echo "  ██╔████╔██║ ██║  ╚████╔╝  ███████║"
    echo "  ██║╚██╔╝██║ ██║   ╚██╔╝   ██╔══██║"
    echo "  ██║ ╚═╝ ██║ ██║    ██║    ██║  ██║"
    echo "  ╚═╝     ╚═╝ ╚═╝    ╚═╝    ╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "  ${DIM}DDD Pentest Agent — 0day · 1day · CTF${NC}"
    echo ""
}

check_deps() {
    local missing=()

    if ! command -v git &>/dev/null; then
        missing+=("git")
    fi

    if ! command -v uv &>/dev/null; then
        warn "uv not found. Installing..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.local/bin:$PATH"
        if ! command -v uv &>/dev/null; then
            err "Failed to install uv"
            exit 1
        fi
        ok "uv installed"
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        err "Missing dependencies: ${missing[*]}"
        err "Install them and try again."
        exit 1
    fi
}

do_install() {
    banner
    info "Installing Miya to ${INSTALL_DIR}..."

    check_deps

    if [ -d "$INSTALL_DIR" ]; then
        warn "Directory exists: ${INSTALL_DIR}"
        warn "Switching to update mode..."
        do_update "$INSTALL_DIR"
        return
    fi

    info "Cloning repository..."
    git clone --depth 1 --branch "$BRANCH" "$REPO" "$INSTALL_DIR"

    info "Installing dependencies..."
    cd "$INSTALL_DIR"
    uv sync --extra dev

    # Create shell wrapper
    _install_wrapper

    ok "Miya installed successfully!"
    echo ""
    _print_usage
}

do_update() {
    local dir="${1:-$(pwd)}"

    if [ ! -d "$dir/.git" ]; then
        err "Not a git repository: $dir"
        err "Run the full install instead."
        exit 1
    fi

    cd "$dir"
    banner
    info "Updating Miya..."

    # Save current version
    local old_ver
    old_ver=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

    # Pull latest
    info "Pulling latest changes..."
    git fetch origin "$BRANCH"
    git reset --hard "origin/$BRANCH"

    local new_ver
    new_ver=$(git rev-parse --short HEAD)

    if [ "$old_ver" = "$new_ver" ]; then
        ok "Already up to date (${new_ver})"
    else
        ok "Updated: ${old_ver} → ${new_ver}"
    fi

    # Reinstall deps
    info "Syncing dependencies..."
    uv sync --extra dev

    ok "Update complete!"
    echo ""

    # Show changelog
    if [ "$old_ver" != "$new_ver" ] && [ "$old_ver" != "unknown" ]; then
        info "Changes since ${old_ver}:"
        git log --oneline "${old_ver}..${new_ver}" 2>/dev/null | head -20
        echo ""
    fi
}

_install_wrapper() {
    local bin_dir="$HOME/.local/bin"
    mkdir -p "$bin_dir"

    cat > "$bin_dir/miya" << WRAPPER
#!/usr/bin/env bash
exec uv run --project "$INSTALL_DIR" miya "\$@"
WRAPPER
    chmod +x "$bin_dir/miya"

    # Check PATH
    if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
        warn "Add to your shell profile:"
        echo "  export PATH=\"$bin_dir:\$PATH\""
        echo ""
    fi
}

_print_usage() {
    echo -e "${BOLD}Quick start:${NC}"
    echo ""
    echo -e "  ${GREEN}miya interactive${NC}              # Interactive REPL"
    echo -e "  ${GREEN}miya oneday -t 192.168.1.1${NC}    # 1-day exploit"
    echo -e "  ${GREEN}miya zeroday -t ./app${NC}         # 0-day discovery"
    echo -e "  ${GREEN}miya ctf -t ./chall -c web${NC}    # CTF solve"
    echo ""
    echo -e "${BOLD}Configuration:${NC}"
    echo ""
    echo -e "  export ANTHROPIC_API_KEY=sk-ant-..."
    echo -e "  export MIYA_MODEL=opus  ${DIM}# opus/sonnet/haiku${NC}"
    echo ""
    echo -e "${BOLD}Update:${NC}"
    echo ""
    echo -e "  cd ${INSTALL_DIR} && make update"
    echo -e "  ${DIM}# or: ./install.sh update${NC}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

case "${1:-install}" in
    install)
        do_install
        ;;
    update|upgrade)
        do_update "${2:-$(pwd)}"
        ;;
    --help|-h)
        echo "Usage: install.sh [install|update]"
        echo ""
        echo "  install   Clone repo, install deps, add 'miya' to PATH (default)"
        echo "  update    Pull latest + re-sync deps"
        echo ""
        echo "Environment:"
        echo "  MIYA_DIR      Install directory (default: ~/miya-bot)"
        echo "  MIYA_BRANCH   Git branch (default: main)"
        ;;
    *)
        err "Unknown command: $1"
        echo "Usage: install.sh [install|update]"
        exit 1
        ;;
esac

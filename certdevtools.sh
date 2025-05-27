#!/usr/bin/env bash
set -e

# === GLOBAL LOGGING ===
log() { echo "[$(date '+%F %T')] $1"; }
log_info() { log "ℹ️ $1"; }
log_success() { log "✅ $1"; }
log_warn() { log "⚠️ $1"; }
log_error() { echo "[$(date '+%F %T')] ❌ $1" >&2; }

# === DETECT OS ===
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
else
    log_error "Unsupported OS. Exiting."
    exit 1
fi

log_info "Detected Linux distribution: $ID ($VERSION_CODENAME)"

# === DETECT WSL ===
IS_WSL=false
if grep -qi microsoft /proc/version; then
    IS_WSL=true
    log_info "WSL environment detected"
fi

# === PACKAGE LIST ===
COMMON_PACKAGES=(
  python3 python3-pip python3-devel pipx
  gcc gcc-c++ make cmake
  git curl wget unzip gh
  openssh-clients
  openssl-devel libffi-devel zlib-devel
  vim nano
  buildah skopeo podman-compose jq
  kernel-devel glibc-static strace lsof
  nodejs golang
  dotnet-sdk-8.0 dotnet-sdk-6.0
  htop tree ncdu fd ripgrep bat
  gnupg pinentry gnutls-utils sequoia-sq
  net-tools bind-utils tcpdump nmap iperf3
  shellcheck shfmt fzf tldr btop
  ansible
)

# === INSTALL DEV TOOLS ===
install_dev_tools() {
    log_info "Installing development tools for $ID..."

    if [[ "$ID" == "fedora" || "$ID_LIKE" =~ "rhel" ]]; then
        sudo dnf install -y https://packages.microsoft.com/config/fedora/39/packages-microsoft-prod.rpm || true
        sudo dnf update -y

        log_info "Filtering Fedora package list..."

        local pkgs_to_install=()
        for pkg in "${COMMON_PACKAGES[@]}" python3-venv; do
            if dnf list --installed "$pkg" &>/dev/null; then
                log_info "Already installed: $pkg"
            elif dnf list "$pkg" &>/dev/null; then
                pkgs_to_install+=("$pkg")
            else
                log_warn "Unavailable package (skipped): $pkg"
            fi
        done

        if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then
            sudo dnf install -y "${pkgs_to_install[@]}"
        else
            log_info "All packages already installed or unavailable."
        fi

        # PowerShell: Manual install
        if ! command -v pwsh &>/dev/null; then
            log_info "Installing PowerShell from tar.gz archive..."
            # Download the powershell '.tar.gz' archive
            curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.5.1/powershell-7.5.1-linux-x64.tar.gz
            # Create the target folder where powershell will be placed
            sudo mkdir -p /opt/microsoft/powershell/7
            # Expand powershell to the target folder
            sudo tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7
            # Set execute permissions
            sudo chmod +x /opt/microsoft/powershell/7/pwsh
            # Create the symbolic link that points to pwsh
            sudo ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh
        else
            log_info "PowerShell already installed"
        fi

    elif [[ "$ID" == "ubuntu" || "$ID_LIKE" =~ "debian" ]]; then
        wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb
        sudo dpkg -i packages-microsoft-prod.deb
        rm packages-microsoft-prod.deb
        sudo apt update

        sudo apt install -y "${COMMON_PACKAGES[@]}" python3-venv powershell
    else
        log_error "Unsupported distro: $ID"
        exit 1
    fi
}

# === SYSTEM + APP-LEVEL CERT SETUP ===
setup_enterprise_trust() {
    local zscaler_cert="/mnt/c/Users/639016/Certs/ZscalerRootCertificate-2048-SHA256.crt"
    local cert_content=""
    local python_cert=""
    local git_ca=""
    local node_cert_dir="$HOME/.node-certs"

    if [[ ! -f "$zscaler_cert" ]]; then
        log_warn "Zscaler cert not found at $zscaler_cert. Skipping trust setup."
        return
    fi

    log_info "Reading and injecting Zscaler certificate..."
    cert_content=$(sed '/^\s*$/d' "$zscaler_cert")

    # === System trust ===
    if [[ "$ID" == "ubuntu" || "$ID_LIKE" =~ "debian" ]]; then
        sudo cp "$zscaler_cert" "/usr/local/share/ca-certificates/zscaler.crt"
        sudo update-ca-certificates
        log_success "System trust updated (Ubuntu)"
    elif [[ "$ID" == "fedora" || "$ID_LIKE" =~ "rhel" ]]; then
        sudo cp "$zscaler_cert" "/etc/pki/ca-trust/source/anchors/zscaler.crt"
        sudo update-ca-trust extract
        log_success "System trust updated (Fedora)"
    else
        log_warn "Unsupported distro for CA trust update"
    fi

    # === Python certifi (pip) ===
    python_cert=$(python3 -m certifi 2>/dev/null || true)
    if [[ -f "$python_cert" ]]; then
        cp "$python_cert" "$python_cert.bak"
        if ! grep -q "$cert_content" "$python_cert"; then
            echo -e "\n$cert_content" >> "$python_cert"
            log_info "✅ Appended cert to Python certifi store"
        else
            log_info "Python certifi already contains the cert"
        fi
    else
        log_warn "Python certifi store not found"
    fi

    # === Git CA (if manually configured) ===
    git_ca=$(git config --get http.sslcainfo || true)
    if [[ -n "$git_ca" && -f "$git_ca" ]]; then
        cp "$git_ca" "$git_ca.bak"
        if ! grep -q "$cert_content" "$git_ca"; then
            echo -e "\n$cert_content" >> "$git_ca"
            log_info "✅ Appended cert to Git CA bundle"
        else
            log_info "Git CA already contains the cert"
        fi
    else
        log_info "Git using system trust or no custom CA"
    fi

    # === Node.js CA ===
    log_info "Setting up Node.js certificate trust..."
    mkdir -p "$node_cert_dir"
    cp "$zscaler_cert" "$node_cert_dir/zscaler.crt"
    chmod 644 "$node_cert_dir/zscaler.crt"
    
    # Add NODE_EXTRA_CA_CERTS to bashrc if not already there
    if ! grep -q 'NODE_EXTRA_CA_CERTS' ~/.bashrc; then
        echo "export NODE_EXTRA_CA_CERTS=\"$node_cert_dir/zscaler.crt\"" >> ~/.bashrc
        log_success "Added NODE_EXTRA_CA_CERTS to ~/.bashrc"
    else
        log_info "NODE_EXTRA_CA_CERTS already configured in ~/.bashrc"
    fi
    
    # Export for current session
    export NODE_EXTRA_CA_CERTS="$node_cert_dir/zscaler.crt"
    log_success "Node.js certificate trust configured"
}

# === INSTALL NVM AND NODE LTS ===
install_nvm_node() {
    log_info "Installing NVM and Node.js..."
    export NVM_VERSION="v0.39.7"
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/$NVM_VERSION/install.sh | bash

    export NVM_DIR="$HOME/.nvm"
    . "$NVM_DIR/nvm.sh"

    # Install LTS version (stable)
    log_info "Installing Node.js LTS version..."
    nvm install --lts
    nvm alias default 'lts/*'
    
    # Optionally install latest version
    log_info "Installing latest Node.js version..."
    nvm install node
    
    # Use LTS version by default
    nvm use default
    
    log_info "Current Node.js version: $(node -v)"
    log_info "Available Node.js versions:"
    nvm ls
    
    log_info "To switch to the latest version, use: nvm use node"
    log_info "To switch back to LTS, use: nvm use default"

    if ! grep -q 'NVM_DIR' ~/.bashrc; then
        echo 'export NVM_DIR="$HOME/.nvm"' >> ~/.bashrc
        echo '[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"' >> ~/.bashrc
    fi
}

# === MAIN ===
main() {
    install_dev_tools
    setup_enterprise_trust
    install_nvm_node
    log_success "🎉 Developer environment setup complete!"
}

main "$@"

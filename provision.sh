#!/bin/bash
# VM provisioning script for Podman machine Fedora VM

set -e

echo "Starting VM provisioning..."

# Install Zscaler certificate
echo "Installing Zscaler certificate..."
sudo mkdir -p /etc/pki/ca-trust/source/anchors/
sudo cp ~/ZscalerRootCertificate-2048-SHA256.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust extract

# Configure Git to use custom CA bundle
echo "Configuring Git CA bundle..."
git config --global http.sslCAInfo ~/.git-ca-bundle.pem

# Install additional packages
echo "Installing additional packages..."
sudo dnf check-update || true
sudo dnf install -y \
  curl \
  jq \
  vim \
  htop \
  net-tools \
  iputils \
  bind-utils \
  procps-ng \
  iproute

# Configure Windows container support
echo "Configuring Windows container support..."
sudo podman pull mcr.microsoft.com/windows/nanoserver:ltsc2022

# Configure container directories and permissions
echo "Setting up container configuration directories..."
mkdir -p ~/.config/containers
chmod 700 ~/.config/containers

# If auth.json exists, set proper permissions
if [ -f ~/.config/containers/auth.json ]; then
    chmod 600 ~/.config/containers/auth.json
    echo "Container authentication configured"
fi

# Reload systemd configuration if containers.conf was updated
if [ -f ~/.config/containers/containers.conf ]; then
    echo "Container runtime configuration applied"
fi

# Enable podman socket for remote connections (optional)
echo "Enabling podman socket..."
systemctl --user enable --now podman.socket
systemctl --user status podman.socket

# Set lingering for current user to keep services running
loginctl enable-linger $(whoami)

echo "VM provisioning completed successfully!"

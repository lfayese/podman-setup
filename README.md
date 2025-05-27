# Windows 11 Container Environment Setup

This project provides a comprehensive container development environment setup for Windows 11, combining Podman VM setup for Linux containers and native Windows container tools installation.

## Overview

The solution consists of two main scripts:

1. **ContainerSetup.ps1**: The main PowerShell script that orchestrates the entire setup process
2. **provision.sh**: A bash script that runs inside the Podman VM to configure the Linux environment

These scripts automate the following tasks:

- Setting up a Podman VM with Fedora Linux & Windows container support
- Installing and configuring containerd, CNI plugins, nerdctl, cri-tools, BuildKit
- Configuring OpenSSH for remote management
- Installing certificates and configuring Git in the VM
- Enabling podman socket for remote connections
- Testing Windows container functionality

## Prerequisites

- Windows 11 with Hyper-V and Containers features enabled
- Podman for Windows installed
- PowerShell 7+ recommended
- Administrator privileges
- Required certificates:
  - Zscaler Root Certificate
  - Git CA bundle
- Custom .bashrc file (optional)
- SSH public key for Windows container tools setup (optional - will use Podman Desktop keys if not provided)

## Installation

1. Clone or download this repository to your local machine
2. Ensure all prerequisites are met
3. Run the PowerShell script with appropriate parameters

## Usage

### Basic Usage

```powershell
# Setup both Podman VM and Windows container tools (using Podman Desktop SSH keys)
.\ContainerSetup.ps1

# Setup both with custom SSH key
.\ContainerSetup.ps1 -SSHPublicKey "ssh-rsa AAAA..."

# Setup only Podman VM
.\ContainerSetup.ps1 -SetupWindowsTools $false

# Setup only Windows container tools
.\ContainerSetup.ps1 -SetupPodmanVM $false
```

### Advanced Usage

```powershell
# Customize Podman VM specifications
.\ContainerSetup.ps1 `
  -MachineName "custom-podman-vm" `
  -VMCpus 8 `
  -VMMemoryMB 16384 `
  -VMDiskSizeGB 200 `  -CertificatePath "C:\path\to\cert.crt" `
  -GitCABundlePath "C:\path\to\ca-bundle.pem" `
  -BashrcPath "C:\path\to\custom.bashrc"
```

## Parameters

### Podman VM Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| MachineName | Name of the Podman machine to create | podman-machine-default |
| CertificatePath | Path to Zscaler Root Certificate | $env:USERPROFILE\Certs\ZscalerRootCertificate-2048-SHA256.crt |
| GitCABundlePath | Path to Git CA bundle | $env:USERPROFILE\Certs\git-ca-bundle.pem |
| BashrcPath | Path to custom .bashrc file | C:\Tools\podman-setup.bashrc |
| VMCpus | Number of CPUs to allocate | 6 |
| VMMemoryMB | Amount of memory (MB) to allocate | 8096 |
| VMDiskSizeGB | Disk size (GB) for the VM | 110 |
| IsRootful | Whether to create a rootful Podman machine | $true |

### Windows Container Tools Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| SSHPublicKey | Public key for Administrators' authorized_keys | No (uses Podman Desktop keys if not provided) |

### Setup Control Flags

| Parameter | Description | Default |
|-----------|-------------|---------|
| SetupPodmanVM | Whether to set up the Podman VM | $true |
| SetupWindowsTools | Whether to set up Windows container tools | $true |

### Common Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| MaxRetries | Maximum number of retries for operations | 3 |
| RetryDelaySeconds | Delay between retries in seconds | 5 |

## Enhanced SSH Key Handling for Multiple VMs

The scripts have been improved to better handle SSH key authentication when working with multiple Podman VMs:

1. **Automatic key detection**: The scripts now check for both machine-specific SSH keys and Podman Desktop keys.

2. **Key prioritization**: When connecting to a VM:
   - First, the scripts attempt to use the VM's own machine-specific keys (from `podman machine inspect`)
   - If those aren't available or don't work, the scripts fall back to Podman Desktop keys

3. **Improved diagnostics**: Use the diagnostic tool to verify SSH key configuration:

   ```powershell
   .\Diagnose-PodmanVM.ps1 -VMName "your-machine-name"
   ```

4. **Key location awareness**: The scripts report which keys are being used, helping to troubleshoot connection issues.

### Multiple VM Configuration

When working with multiple Podman VMs, use the deployment script to configure each one:

```powershell
# Deploy configs to different machines
.\Deploy-ContainerConfigs.ps1 -MachineName "podman-machine-1"
.\Deploy-ContainerConfigs.ps1 -MachineName "podman-machine-2"

# Test configuration on a specific machine
.\Test-ContainerConfigs.ps1 -MachineName "podman-machine-1"
```

See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for more details on SSH key handling and resolving common issues.

## Testing Your Environment

After setting up your container environment, you can verify that everything is working correctly using the included test script:

```powershell
# Test both Podman VM and Windows container tools
.\Test-ContainerEnvironment.ps1

# Test only Podman VM
.\Test-ContainerEnvironment.ps1 -SkipWindowsToolsTests $true

# Test only Windows container tools
.\Test-ContainerEnvironment.ps1 -SkipPodmanTests $true
```

The test script performs the following checks:

### Podman VM Tests

- Verifies Podman is installed and accessible
- Checks Podman machine status
- Tests Linux container functionality
- Tests Windows container functionality in Podman
- Verifies Podman socket is active in the Fedora VM

### Windows Container Tools Tests

- Verifies containerd service is running
- Checks nerdctl installation and functionality
- Tests Windows container functionality with nerdctl
- Verifies crictl installation
- Checks BuildKit service status
- Verifies SSH service is running

Each test will display a pass/fail status with relevant details, helping you identify any issues with your setup.

## Troubleshooting

### Common Issues

1. **Elevation Error**: Ensure you're running PowerShell as Administrator
2. **Missing Certificates**: Verify certificate paths are correct
3. **Windows Features**: Ensure Hyper-V and Containers features are enabled
4. **Podman Not Found**: Ensure Podman is installed and in your PATH
5. **Network Issues**: Check your network connection for downloading components
6. **Container Image Pull Failures**: Check your internet connection and proxy settings
7. **SSH Key Issues**: Verify your SSH public key format is correct

### Logs

The script creates a detailed log file in your TEMP directory. The path is displayed at the end of the script execution. Check this log for detailed error information.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

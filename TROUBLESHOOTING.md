# Podman VM Configuration Troubleshooting Guide

This guide will help you address issues with Podman VM configuration and the `null` output you encountered when running the configuration scripts.

## Quick Fix

Try these steps in order to resolve the issue:

1. **Restart your Podman machine**

   ```powershell
   podman machine stop podman-machine-default
   podman machine start podman-machine-default
   ```

2. **Install jq in the VM**

   ```powershell
   podman machine ssh podman-machine-default "sudo dnf install -y jq"
   ```

3. **Re-run the deployment script**

   ```powershell
   .\Deploy-ContainerConfigs.ps1 -MachineName "podman-machine-default"
   ```

## Understanding The Issue

The `null` output you saw when running `podman info --format json | jq -r '.host.configFile'` was likely caused by one of these issues:

1. **Missing jq tool**: The jq tool might not be installed in the VM
2. **Invalid JSON path**: The `.host.configFile` path may not exist in your Podman version
3. **VM restart needed**: Some configuration changes require a VM restart

## Updating to cgroups-v2

If you're seeing deprecation warnings about cgroups-v1 with Podman v5, you should consider upgrading to cgroups-v2 which will be required in future versions.

### Temporary Solution

To temporarily suppress the cgroups-v1 deprecation warning, you can set this environment variable:

```powershell
$env:PODMAN_IGNORE_CGROUPSV1_WARNING=1
```

Or place it in your PowerShell profile to make it persistent.

### Permanent Solution - Upgrade to cgroups-v2

To upgrade to cgroups-v2 in your Podman VM:

1. **Stop your Podman machine**

   ```powershell
   podman machine stop podman-machine-default
   ```

2. **Update the VM configuration**

   ```powershell
   # This command configures the VM to use systemd for cgroup management
   # which effectively enables cgroups-v2 in the Podman VM
   podman machine set --rootful --cgroup-manager systemd podman-machine-default
   ```

3. **Start the machine again**

   ```powershell
   podman machine start podman-machine-default
   ```

4. **Verify cgroups-v2 is now in use**

   ```powershell
   # Check cgroup version in Podman info
   podman machine ssh podman-machine-default "podman info --format '{{.Host.CgroupVersion}}'"
   ```

   If this outputs "v2", it confirms that cgroups-v2 is working correctly.

5. **Test Podman without warnings**

   ```powershell
   podman machine ssh podman-machine-default "podman version"
   ```

   The warning about cgroups-v1 should no longer appear.

6. **If you still see cgroups-v1 warnings**

   In some Podman VM configurations, additional steps may be required:

   ```powershell
   # Stop the machine again
   podman machine stop podman-machine-default

   # Remove and recreate the machine with cgroups-v2 enabled
   podman machine rm podman-machine-default
   podman machine init --rootful --cgroup-manager=systemd --now podman-machine-default

   # After recreation, run the Deploy-ContainerConfigs.ps1 script again to restore your settings
   .\Deploy-ContainerConfigs.ps1 -MachineName "podman-machine-default"
   ```

## Detailed Diagnostics

If the quick fix didn't work, follow these detailed steps:

### Check Podman Version and Capabilities

```powershell
# Check Podman version in VM
podman machine ssh podman-machine-default "podman version"

# Examine detailed info structure
podman machine ssh podman-machine-default "podman info --format json | jq ."

# Check config directory contents
podman machine ssh podman-machine-default "ls -la ~/.config/containers/"

# Check file permissions
podman machine ssh podman-machine-default "stat ~/.config/containers/*"
```

### Verify SSH Access

```powershell
# Test direct SSH access
ssh -i "C:\Users\639016\.local\share\containers\podman\machine\machine" -p 62204 -l core localhost "echo SSH Test Successful"
```

### Run The Diagnostic Tool

```powershell
# Run the diagnostic script
.\Diagnose-PodmanVM.ps1
```

## Tips for Rootful vs. Rootless

- **Rootful Mode**: Configuration files are in `/root/.config/containers/`
- **Rootless Mode**: Configuration files are in `/home/core/.config/containers/`

The updated scripts now detect this automatically and use the correct paths.

## Manual Configuration Verification

If you need to manually verify configurations:

```powershell
# Check if configs are properly placed
podman machine ssh podman-machine-default "find ~/.config/containers -type f | xargs cat"

# Verify registry authentication
podman machine ssh podman-machine-default "podman login --get-login quay.io"
```

## SSH TTY Errors

If you see errors like `stty: 'standard input': Inappropriate ioctl for device` when running the scripts:

### What's Happening

This is a harmless warning that occurs when SSH tries to manipulate terminal settings in non-interactive mode.

### The Fix

The scripts have been updated to use the SSH `-T` flag which disables pseudo-terminal allocation and fixes this issue. You should no longer see these errors after the update.

### Manual Solution

If you still encounter this issue, you can manually execute SSH commands with:

```powershell
ssh -T -i <key-path> -p <port> user@localhost "TERM=dumb <your-command>"
```

## SSH Key Handling for Multiple Podman VMs

When working with multiple Podman VMs, SSH key handling becomes more complex. Here's how to troubleshoot SSH key issues:

### Understanding Podman SSH Keys

Podman uses two potential sets of SSH keys:

1. **Machine-specific keys**: Each VM has its own SSH key pair generated at creation time
2. **Podman Desktop keys**: Global keys used by Podman Desktop

Our scripts have been updated to prioritize machine-specific keys when available, falling back to Podman Desktop keys when necessary.

### Diagnosing SSH Key Issues

If you're having SSH connection problems with multiple VMs:

1. **Run the diagnostic tool**:

   ```powershell
   .\Diagnose-PodmanVM.ps1 -VMName "your-machine-name"
   ```

2. **Check which keys are being used**:

   ```powershell
   podman machine inspect your-machine-name | Select-String -Pattern "Identity"
   ```

3. **Verify key existence**:

   ```powershell
   # The path will be shown in the output of the previous command
   Test-Path "C:\path\to\your\vm\ssh\key"
   ```

### Common SSH Key Problems

1. **Key path hardcoding**: If you see errors about missing SSH keys at `C:\Users\639016\...`, you may need to update hardcoded paths to use your username.

2. **Permission issues**: Ensure SSH keys have proper permissions:

   ```powershell
   icacls "C:\path\to\ssh\key" /grant:r "$env:USERNAME:(R)"
   ```

3. **Multiple VM conflict**: If using the same key for multiple VMs, ensure each authorized_keys file contains the correct public key.

4. **VM-specific vs. Desktop keys**: Our updated scripts attempt to use VM-specific keys first. If these fail, check if Podman Desktop keys work instead:

   ```powershell
   $desktopKey = "$env:USERPROFILE\.local\share\containers\podman\machine\machine"
   ssh -i $desktopKey -p <VM_PORT> <VM_USER>@localhost "echo Test successful"
   ```

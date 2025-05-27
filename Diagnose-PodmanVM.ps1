# Quick Troubleshooting Script for Podman VM Config
# This script provides basic diagnostic info about a Podman VM
# No dependencies required

param(
    [string]$VMName = "podman-machine-default"
)

Write-Host "🔍 PODMAN VM DIAGNOSTICS" -ForegroundColor Cyan
Write-Host "====================`n" -ForegroundColor Cyan

# Get machine info
Write-Host "📋 Podman Machine Info:" -ForegroundColor Yellow
& podman machine list

# Get machine details
Write-Host "`n📊 Machine Inspection:" -ForegroundColor Yellow
$machineInfo = & podman machine inspect $VMName 2>&1
if ($machineInfo -match "Error") {
    Write-Host "Error: Cannot inspect machine. Is it running?" -ForegroundColor Red
} else {
    $info = $machineInfo | ConvertFrom-Json
    Write-Host "  Name: $($info.Name)"
    Write-Host "  Created: $($info.Created)"
    Write-Host "  Rootful: $($info.Rootful)"
    Write-Host "  SSH Port: $($info.SSHConfig.Port)"
    Write-Host "  SSH User: $($info.SSHConfig.User)"
    Write-Host "  Key Path: $($info.SSHConfig.IdentityPath)"
}

# Check SSH keys
Write-Host "`n🔑 SSH Key Check:" -ForegroundColor Yellow

# Check Machine-specific SSH keys
$machineKeyPath = $info.SSHConfig.IdentityPath
$machineKeyExists = $false

if ($machineKeyPath -and (Test-Path $machineKeyPath)) {
    $machineKeyExists = $true
    Write-Host "  ✅ Machine-specific private key found: $machineKeyPath" -ForegroundColor Green

    $machinePublicKeyPath = "$machineKeyPath.pub"
    if (Test-Path $machinePublicKeyPath) {
        Write-Host "  ✅ Machine-specific public key found: $machinePublicKeyPath" -ForegroundColor Green
        $machinePubKeyContent = Get-Content $machinePublicKeyPath -Raw
        Write-Host "  Machine Key: $($machinePubKeyContent.Substring(0, 30))..." -ForegroundColor Gray
    } else {
        Write-Host "  ❌ Machine-specific public key missing: $machinePublicKeyPath" -ForegroundColor Red
    }
} else {
    Write-Host "  ❌ Machine-specific key missing or invalid path: $(if ($machineKeyPath) { $machineKeyPath } else { 'Not specified' })" -ForegroundColor Yellow
}

# Always check Podman Desktop SSH keys as fallback
$privateKeyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine"
$publicKeyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine.pub"

Write-Host "`n  Podman Desktop Keys (fallback):" -ForegroundColor Cyan
if (Test-Path $privateKeyPath) {
    Write-Host "  ✅ Podman Desktop private key found: $privateKeyPath" -ForegroundColor Green
} else {
    Write-Host "  ❌ Podman Desktop private key missing: $privateKeyPath" -ForegroundColor Red
}

if (Test-Path $publicKeyPath) {
    Write-Host "  ✅ Podman Desktop public key found: $publicKeyPath" -ForegroundColor Green
    $pubKeyContent = Get-Content $publicKeyPath -Raw
    Write-Host "  Podman Desktop Key: $($pubKeyContent.Substring(0, 30))..." -ForegroundColor Gray
} else {
    Write-Host "  ❌ Podman Desktop public key missing: $publicKeyPath" -ForegroundColor Red
}

# Test SSH connection
Write-Host "`n📡 Testing SSH Connection:" -ForegroundColor Yellow

# First test with machine-specific key if available
if ($machineKeyExists) {
    try {
        $user = $info.SSHConfig.User
        $port = $info.SSHConfig.Port
        $keyPath = $machineKeyPath

        Write-Host "  Testing with machine-specific key..." -ForegroundColor Cyan

        $sshArgs = @(
            '-i', $keyPath,
            '-p', $port,
            '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'IdentitiesOnly=yes',
            # Add -T flag to disable pseudo-terminal allocation (fixes stty errors)
            '-T',
            "$user@localhost",
            # Modify the command to avoid terminal control characters
            "TERM=dumb echo 'SSH connection successful with machine key'"
        )

        $result = & ssh @sshArgs 2>&1
        if ($result -match "successful") {
            Write-Host "  ✅ SSH connection with machine-specific key successful" -ForegroundColor Green
        } else {
            Write-Host "  ❌ SSH connection with machine-specific key failed: $result" -ForegroundColor Red
        }
    } catch {
        Write-Host "  ❌ SSH connection with machine-specific key test failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Always test with Podman Desktop key as fallback
try {
    $user = $info.SSHConfig.User
    $port = $info.SSHConfig.Port
    $keyPath = $privateKeyPath  # Podman Desktop key

    Write-Host "  Testing with Podman Desktop key..." -ForegroundColor Cyan

    $sshArgs = @(
        '-i', $keyPath,
        '-p', $port,
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'IdentitiesOnly=yes',
        # Add -T flag to disable pseudo-terminal allocation (fixes stty errors)
        '-T',
        "$user@localhost",
        # Modify the command to avoid terminal control characters
        "TERM=dumb echo 'SSH connection successful with Podman Desktop key'"
    )

    $result = & ssh @sshArgs 2>&1
    if ($result -match "successful") {
        Write-Host "  ✅ SSH connection with Podman Desktop key successful" -ForegroundColor Green
    } else {
        Write-Host "  ❌ SSH connection with Podman Desktop key failed: $result" -ForegroundColor Red
    }
} catch {
    Write-Host "  ❌ SSH connection with Podman Desktop key test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🧰 Next Steps:" -ForegroundColor Magenta
Write-Host " - Restart the machine: podman machine stop $VMName && podman machine start $VMName"
Write-Host " - Run the deployment script with -Verbose: .\Deploy-ContainerConfigs.ps1 -MachineName `"$VMName`" -Verbose"
Write-Host " - Check file permissions in VM: podman machine ssh $VMName ls -la ~/.config/containers/"
Write-Host " - Verify podman working in VM: podman machine ssh $VMName podman info"

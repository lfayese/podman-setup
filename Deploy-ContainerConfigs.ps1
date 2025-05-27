# Deploy Container Config Files to Podman VM
# This script copies container configuration files to an existing Podman VM

[CmdletBinding()]
Param(
    [string]$MachineName = 'podman-machine-default',
    [string]$ContainersConfigDir = (Join-Path $PSScriptRoot 'containers')
)

# Source the main script functions
$mainScript = Join-Path $PSScriptRoot 'ContainerSetup.ps1'
if (Test-Path $mainScript) {
    # Extract functions from main script (simplified approach)
    # In practice, you'd want to put shared functions in a module
    Write-Host "Loading functions from main script..." -ForegroundColor Cyan
} else {
    Write-Error "Main ContainerSetup.ps1 script not found"
    exit 1
}

function Get-SSHInfo {
    param([string]$Name)

    Write-Host "Retrieving SSH connection info for: $Name" -ForegroundColor Cyan

    # Get the machine information with error handling
    try {
        $machineInfo = & podman machine inspect $Name | ConvertFrom-Json
        if (-not $machineInfo) {
            throw "Machine inspection returned null data"
        }
    }
    catch {
        Write-Host "Error inspecting machine: $_" -ForegroundColor Red
        throw "Failed to inspect Podman machine '$Name'. Is it running?"
    }

    # Use Podman Desktop keys as default
    $podmanKeyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine"
    $podmanPubKeyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine.pub"

    # Check if the machine has a valid SSH Identity Path (replace ternary with if-else)
    $keyPath = $podmanKeyPath
    $pubKeyPath = $podmanPubKeyPath
    $machineSpecificKeyExists = $false

    if ($machineInfo.SSHConfig.IdentityPath -and (Test-Path $machineInfo.SSHConfig.IdentityPath)) {
        $keyPath = $machineInfo.SSHConfig.IdentityPath
        $pubKeyPath = "$($machineInfo.SSHConfig.IdentityPath).pub"
        $machineSpecificKeyExists = $true
        Write-Host "Using machine-specific SSH key: $keyPath" -ForegroundColor Green
    }
    else {
        Write-Host "Using Podman Desktop SSH key: $podmanKeyPath" -ForegroundColor Yellow
    }

    # Verify the selected SSH key exists
    if (-not (Test-Path $keyPath)) {
        Write-Error "SSH private key not found at: $keyPath"
        throw "SSH private key not found. Please ensure Podman is properly installed."
    }

    # Determine user with fallback
    $user = $null
    if ($machineInfo.SSHConfig.User) {
        $user = $machineInfo.SSHConfig.User
    }
    elseif ($machineInfo.Rootful) {
        $user = 'root'
    }
    else {
        $user = 'core'
    }

    # Ensure we have a port
    $port = 22
    if ($machineInfo.SSHConfig.Port) {
        $port = $machineInfo.SSHConfig.Port
    }

    return @{
        User = $user
        Port = $port
        KeyPath = $keyPath
        PubKeyPath = $pubKeyPath
        UsingMachineKey = $machineSpecificKeyExists
    }
}

function Copy-ToVM {
    param([string]$Src, [string]$Dest, [hashtable]$SSH)

    $user = $SSH.User -replace '^.*\\', ''
    $scpPath = "$env:SystemRoot\System32\OpenSSH\scp.exe"
    
    # Ensure we can find SCP
    if (-not (Test-Path $scpPath)) {
        Write-Host "Warning: Could not find Windows OpenSSH SCP at $scpPath" -ForegroundColor Yellow
        $scpPath = "scp"  # Fall back to PATH-based resolution
    } else {
        Write-Host "Using Windows built-in SCP: $scpPath" -ForegroundColor Green
    }
    
    $scpArgs = @(
        '-i', $SSH.KeyPath
    )
    
    # Only add port if it's specified
    if ($SSH.Port -and $SSH.Port -ne '') {
        $scpArgs += @('-P', $SSH.Port)
    }
    
    $scpArgs += @(
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'PubkeyAuthentication=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'PasswordAuthentication=no',
        '-o', 'BatchMode=yes',
        # Silence warnings about adding hosts to known_hosts
        '-o', 'LogLevel=ERROR',
        $Src,
        # Use 127.0.0.1 instead of localhost for more reliable connections
        "$user@127.0.0.1:$Dest"
    )

    Write-Host "Copying $(Split-Path $Src -Leaf) to VM..." -ForegroundColor Green
    Write-Host "Command: $scpPath $($scpArgs -join ' ')" -ForegroundColor Gray
    & $scpPath @scpArgs
}

function Invoke-InVM {
    param([string]$Cmd, [hashtable]$SSH)

    $user = $SSH.User -replace '^.*\\', ''
    $sshPath = "$env:SystemRoot\System32\OpenSSH\ssh.exe"
    
    # Ensure we can find SSH
    if (-not (Test-Path $sshPath)) {
        Write-Host "Warning: Could not find Windows OpenSSH client at $sshPath" -ForegroundColor Yellow
        $sshPath = "ssh"  # Fall back to PATH-based resolution
    } else {
        Write-Host "Using Windows built-in SSH: $sshPath" -ForegroundColor Green
    }
    
    $sshArgs = @(
        '-i', $SSH.KeyPath
    )
    
    # Only add port if it's specified
    if ($SSH.Port -and $SSH.Port -ne '') {
        $sshArgs += @('-p', $SSH.Port)
    }
    
    $sshArgs += @(
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'PubkeyAuthentication=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'PasswordAuthentication=no',
        '-o', 'BatchMode=yes',
        # Add -T flag to disable pseudo-terminal allocation (fixes stty errors)
        '-T',
        # Use 127.0.0.1 instead of localhost for more reliable connections
        "$user@127.0.0.1",
        # Modify the command to avoid terminal control characters and suppress cgroups warning
        "TERM=dumb PODMAN_IGNORE_CGROUPSV1_WARNING=1 $Cmd"
    )

    Write-Host "Running command in VM: $Cmd" -ForegroundColor Gray
    Write-Host "Using SSH command: $sshPath $($sshArgs -join ' ')" -ForegroundColor Gray
    
    try {
        $result = & $sshPath @sshArgs 2>&1
        if ($null -eq $result) {
            return ""  # Return empty string instead of null
        }
        return $result
    }
    catch {
        Write-Host "SSH command failed: $_" -ForegroundColor Red
        return "ERROR: $($_.Exception.Message)"
    }
}

function Test-RequiredTools {
    param([hashtable]$SSH)

    Write-Host "Checking for required tools in VM..." -ForegroundColor Cyan

    # Check if jq is installed
    $jqInstalled = Invoke-InVM -Cmd "command -v jq &>/dev/null && echo true || echo false" -SSH $SSH

    if ($jqInstalled -eq "false") {
        Write-Host "Installing jq for JSON processing..." -ForegroundColor Yellow
        Invoke-InVM -Cmd "sudo dnf install -y jq" -SSH $SSH
    } else {
        Write-Host "✅ jq is installed" -ForegroundColor Green
    }

    # Check if podman is working
    $podmanVersion = Invoke-InVM -Cmd "podman version || echo 'ERROR: Podman not available'" -SSH $SSH
    if ($null -eq $podmanVersion -or $podmanVersion -match "ERROR") {
        Write-Host "⚠️ Warning: Podman appears to be unavailable or not working properly" -ForegroundColor Red
    } else {
        Write-Host "✅ Podman is installed and working" -ForegroundColor Green
        # Get version details safely
        try {
            if ($podmanVersion -match "Version:\s+(.+)") {
                Write-Host "   Podman version: $($matches[1])" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "   Unable to parse Podman version" -ForegroundColor Yellow
        }
    }

    # Check if the configuration directory exists and is accessible
    $configDirStatus = Invoke-InVM -Cmd "ls -la ~/.config/containers/ 2>/dev/null || echo 'ERROR: Directory not accessible'" -SSH $SSH
    if ($configDirStatus -match "ERROR") {
        Write-Host "⚠️ Container config directory not accessible, creating..." -ForegroundColor Yellow
        Invoke-InVM -Cmd "mkdir -p ~/.config/containers/ && chmod 700 ~/.config/containers/" -SSH $SSH
    } else {
        Write-Host "✅ Container config directory exists" -ForegroundColor Green
    }
}

# Main deployment logic
try {
    Write-Host "Deploying container config files to Podman VM: $MachineName" -ForegroundColor Yellow

    # Get SSH connection info
    $sshInfo = Get-SSHInfo -Name $MachineName

    # Create config directory in VM
    Write-Host "Creating container config directory..." -ForegroundColor Cyan
    Invoke-InVM -Cmd "mkdir -p ~/.config/containers && chmod 700 ~/.config/containers" -SSH $sshInfo

    # Test and install required tools
    Test-RequiredTools -SSH $sshInfo

    # Add note about cgroups v2 and warning suppression
    Write-Host "Note: cgroups-v1 warnings are being suppressed. Consider upgrading to cgroups-v2 for future compatibility." -ForegroundColor Yellow
    
    # Deploy each config file
    $configFiles = @(
        @{ Local = 'auth.json'; Remote = '~/.config/containers/auth.json'; Description = 'Registry authentication' },
        @{ Local = 'containers.conf'; Remote = '~/.config/containers/containers.conf'; Description = 'Container runtime config' },
        @{ Local = 'registries.conf'; Remote = '~/.config/containers/registries.conf'; Description = 'Registry configuration' },
        @{ Local = 'policy.json'; Remote = '~/.config/containers/policy.json'; Description = 'Image signature policy' },
        @{ Local = 'storage.conf'; Remote = '~/.config/containers/storage.conf'; Description = 'Storage configuration' }
    )

    foreach ($config in $configFiles) {
        $localPath = Join-Path $ContainersConfigDir $config.Local
        if (Test-Path $localPath) {
            Write-Host "📁 Deploying $($config.Description)..." -ForegroundColor Green
            Copy-ToVM -Src $localPath -Dest $config.Remote -SSH $sshInfo
        } else {
            Write-Host "⚠️  Skipping $($config.Local) (not found)" -ForegroundColor Yellow
        }
    }

    # Set proper permissions
    Write-Host "Setting file permissions..." -ForegroundColor Cyan
    Invoke-InVM -Cmd "chmod 600 ~/.config/containers/auth.json 2>/dev/null || true" -SSH $sshInfo

    # Test the configuration with better error handling
    Write-Host "Testing Podman configuration..." -ForegroundColor Cyan

    # First check if podman info works at all
    $podmanInfoTest = Invoke-InVM -Cmd "podman info &>/dev/null && echo 'OK' || echo 'ERROR'" -SSH $sshInfo
    if ($podmanInfoTest -match "ERROR") {
        Write-Host "⚠️ Podman info command not working correctly - VM may need to be restarted" -ForegroundColor Yellow
    } else {
        # Try several approaches to get config info
        Write-Host "Getting container configuration info..." -ForegroundColor Cyan

        # Simple direct format query first - use a more reliable format string
        $configInfo = Invoke-InVM -Cmd "podman info --format 'Storage driver: {{.Store.GraphDriverName}}' 2>/dev/null || echo 'Info not available'" -SSH $sshInfo
        Write-Host "   $configInfo" -ForegroundColor Gray

        # Try to get config files through a simpler approach
        Write-Host "   Config files in ~/.config/containers:" -ForegroundColor White
        $configFiles = Invoke-InVM -Cmd "find ~/.config/containers -type f -name '*.json' -o -name '*.conf' 2>/dev/null | sort || echo 'No files found'" -SSH $sshInfo

        # Safer handling of output with robust null checks
        if ($null -ne $configFiles -and $configFiles -ne "" -and $configFiles -ne "No files found") {
            # Convert to array if it's a single string
            if ($configFiles -is [string]) {
                $formattedOutput = $configFiles -replace "`n", "`n      "
            } else {
                $formattedOutput = $configFiles -join "`n      "
            }
            Write-Host "      $formattedOutput" -ForegroundColor Gray
        } else {
            Write-Host "      No config files found" -ForegroundColor Yellow
        }
    }

    # Verify container runtime status
    Write-Host "`n🔍 Verifying container runtime..." -ForegroundColor Cyan
    Invoke-InVM -Cmd "podman version | grep -E 'Version|API'" -SSH $sshInfo

    Write-Host "`n✅ Container config files deployed successfully!" -ForegroundColor Green
    Write-Host "🔧 To ensure all changes take effect, restart the Podman machine:" -ForegroundColor Yellow
    Write-Host "   podman machine stop $MachineName" -ForegroundColor Gray
    Write-Host "   podman machine start $MachineName" -ForegroundColor Gray

} catch {
    Write-Error "Failed to deploy config files: $($_.Exception.Message)"
    exit 1
}

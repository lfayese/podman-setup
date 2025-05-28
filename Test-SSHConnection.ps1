# Test script to verify SSH connectivity to Podman VM

[CmdletBinding()]
param(
    [string]$MachineName = 'podman-machine-default',
    [int]$MaxWaitSeconds = 300,
    [int]$CheckInterval = 10
)

# Define a simple logging function
function Write-Log {
    [CmdletBinding()]
    param(
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level,
        [string]$Message
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'INFO'    { Write-Host $logLine -ForegroundColor Cyan }
        'WARNING' { Write-Host $logLine -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logLine -ForegroundColor Red }
        'SUCCESS' { Write-Host $logLine -ForegroundColor Green }
    }
}

# Test SSH connectivity using multiple methods
function Test-SSHConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$MachineName,
        [int]$MaxWaitSeconds = 300,
        [int]$CheckInterval = 10
    )

    Write-Log -Level INFO -Message "Testing SSH connectivity to $MachineName"
    $elapsed = 0
    $methods = @("podman-ssh", "direct-ssh", "wsl-direct")
    $results = @{}

    foreach ($method in $methods) {
        Write-Log -Level INFO -Message "Testing SSH connection via $method..."
        $success = $false

        try {
            switch ($method) {
                "podman-ssh" {
                    $result = & podman machine ssh $MachineName "echo 'SSH_READY'" 2>&1
                    if ($LASTEXITCODE -eq 0 -and $result -match "SSH_READY") {
                        Write-Log -Level SUCCESS -Message "SSH is ready via podman machine ssh"
                        $success = $true
                    } else {
                        Write-Log -Level WARNING -Message "SSH not ready via podman machine ssh: $result"
                    }
                }
                "direct-ssh" {
                    try {
                        $machineInfo = & podman machine inspect $MachineName | ConvertFrom-Json
                        if ($machineInfo.SSHConfig.Port) {
                            $sshPath = "$env:SystemRoot\System32\OpenSSH\ssh.exe"
                            if (-not (Test-Path $sshPath)) { $sshPath = "ssh" }

                            $keyPath = $machineInfo.SSHConfig.IdentityPath
                            if (-not (Test-Path $keyPath)) {
                                $keyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine"
                            }

                            Write-Log -Level INFO -Message "Using SSH key: $keyPath"
                            Write-Log -Level INFO -Message "Using SSH port: $($machineInfo.SSHConfig.Port)"

                            $sshArgs = @(
                                '-i', $keyPath,
                                '-p', $machineInfo.SSHConfig.Port,
                                '-o', 'StrictHostKeyChecking=no',
                                '-o', 'UserKnownHostsFile=/dev/null',
                                '-o', 'BatchMode=yes',
                                '-T',
                                "$($machineInfo.SSHConfig.User)@localhost",
                                "echo 'SSH_READY'"
                            )

                            Write-Log -Level INFO -Message "SSH command: $sshPath $($sshArgs -join ' ')"
                            $directResult = & $sshPath @sshArgs 2>&1
                            Write-Log -Level INFO -Message "SSH result: $directResult"

                            if ($LASTEXITCODE -eq 0 -and $directResult -match "SSH_READY") {
                                Write-Log -Level SUCCESS -Message "SSH is ready via direct SSH connection"
                                $success = $true
                            } else {
                                Write-Log -Level WARNING -Message "SSH not ready via direct SSH connection: $directResult"
                            }
                        } else {
                            Write-Log -Level WARNING -Message "No SSH port found in machine info"
                        }
                    } catch {
                        Write-Log -Level ERROR -Message "Direct SSH connection attempt failed: $_"
                    }
                }
                "wsl-direct" {
                    try {
                        # Try WSL direct access as last resort
                        $wslResult = & wsl -d $MachineName -e echo "WSL_READY" 2>&1
                        if ($wslResult -match "WSL_READY") {
                            Write-Log -Level SUCCESS -Message "WSL direct access works"
                            $success = $true
                        } else {
                            Write-Log -Level WARNING -Message "WSL direct access failed: $wslResult"
                        }
                    } catch {
                        Write-Log -Level ERROR -Message "WSL direct access attempt failed: $_"
                    }
                }
            }
        }
        catch {
            Write-Log -Level ERROR -Message "SSH connection attempt via $method failed: $_"
        }

        $results[$method] = $success
    }

    # Display summary
    Write-Log -Level INFO -Message "SSH connectivity test results:"
    foreach ($method in $methods) {
        $status = if ($results[$method]) { "SUCCESS" } else { "FAILED" }
        Write-Log -Level INFO -Message "  $method $status"
    }

    # Return true if any method succeeded
    return ($results.Values -contains $true)
}

# Get machine info
function Get-MachineInfo {
    [CmdletBinding()]
    param([string]$MachineName)

    Write-Log -Level INFO -Message "Getting machine info for $MachineName"

    try {
        $machineInfo = & podman machine inspect $MachineName | ConvertFrom-Json

        Write-Log -Level INFO -Message "Machine info:"
        Write-Log -Level INFO -Message "  Name: $($machineInfo.Name)"
        Write-Log -Level INFO -Message "  Created: $($machineInfo.Created)"
        Write-Log -Level INFO -Message "  Rootful: $($machineInfo.Rootful)"

        if ($machineInfo.SSHConfig) {
            Write-Log -Level INFO -Message "  SSH Config:"
            Write-Log -Level INFO -Message "    Port: $($machineInfo.SSHConfig.Port)"
            Write-Log -Level INFO -Message "    User: $($machineInfo.SSHConfig.User)"
            Write-Log -Level INFO -Message "    Identity Path: $($machineInfo.SSHConfig.IdentityPath)"
        } else {
            Write-Log -Level WARNING -Message "  No SSH config found"
        }

        return $machineInfo
    } catch {
        Write-Log -Level ERROR -Message "Failed to get machine info: $_"
        return $null
    }
}

# Check if machine exists and is running
$machineExists = & podman machine list --format json | ConvertFrom-Json | Where-Object Name -eq $MachineName
if (-not $machineExists) {
    Write-Log -Level ERROR -Message "Machine '$MachineName' does not exist"
    exit 1
}

if ($machineExists.Running -ne $true) {
    Write-Log -Level WARNING -Message "Machine '$MachineName' exists but is not running. Attempting to start..."
    & podman machine start $MachineName
    Start-Sleep -Seconds 10

    # Check again if it's running
    $machineExists = & podman machine list --format json | ConvertFrom-Json | Where-Object Name -eq $MachineName
    if ($machineExists.Running -ne $true) {
        Write-Log -Level ERROR -Message "Failed to start machine '$MachineName'"
        exit 1
    }
}

# Get machine info
$machineInfo = Get-MachineInfo -MachineName $MachineName

# Test SSH connectivity
$sshConnectivity = Test-SSHConnectivity -MachineName $MachineName -MaxWaitSeconds $MaxWaitSeconds -CheckInterval $CheckInterval

if ($sshConnectivity) {
    Write-Log -Level SUCCESS -Message "SSH connectivity test passed"
} else {
    Write-Log -Level ERROR -Message "SSH connectivity test failed"
}

# Test network configuration
Write-Log -Level INFO -Message "Testing network configuration"
try {
    $networkConfig = & podman machine ssh $MachineName "cat ~/.config/containers/containers.conf 2>/dev/null || echo 'File not found'" 2>&1

    if ($networkConfig -match "File not found") {
        Write-Log -Level WARNING -Message "containers.conf not found in VM"
    } else {
        Write-Log -Level INFO -Message "containers.conf content:"
        Write-Log -Level INFO -Message $networkConfig

        if ($networkConfig -match 'slirp4netns') {
            Write-Log -Level SUCCESS -Message "Network configuration is set to use slirp4netns"
        } else {
            Write-Log -Level WARNING -Message "Network configuration is not set to use slirp4netns"
        }
    }
} catch {
    Write-Log -Level ERROR -Message "Failed to test network configuration: $_"
}

# Final summary
Write-Log -Level INFO -Message "Test completed"

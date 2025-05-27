# Test Container Configuration in Podman VM
# This script verifies that container config files are properly deployed and working

[CmdletBinding()]
Param(
    [string]$MachineName = 'podman-machine-default'
)

function Get-SSHInfo {
    param([string]$Name)

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

function Invoke-InVM {
    param([string]$Cmd, [hashtable]$SSH)

    $user = $SSH.User -replace '^.*\\', ''
    $sshArgs = @(
        '-i', $SSH.KeyPath,
        '-p', $SSH.Port,
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'PubkeyAuthentication=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'PasswordAuthentication=no',
        '-o', 'BatchMode=yes',
        # Add -T flag to disable pseudo-terminal allocation (fixes stty errors)
        '-T',
        "$user@localhost",
        # Modify the command to avoid terminal control characters
        "TERM=dumb $Cmd"
    )

    try {
        $result = & ssh @sshArgs 2>&1
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
    }

    # Check if podman is working
    $podmanWorking = Invoke-InVM -Cmd "podman --version &>/dev/null && echo true || echo false" -SSH $SSH

    if ($podmanWorking -eq "false") {
        Write-Host "⚠️ Warning: Podman appears to be unavailable or not working properly" -ForegroundColor Red
    } else {
        Write-Host "✅ Podman is installed and working" -ForegroundColor Green
    }
}

try {
    Write-Host "🔍 Testing container configuration in Podman VM: $MachineName" -ForegroundColor Yellow

    $sshInfo = Get-SSHInfo -Name $MachineName

    # Test and install required tools
    Test-RequiredTools -SSH $sshInfo

    # Test container config files
    $configTests = @(
        @{ File = '~/.config/containers/auth.json'; Name = 'Registry Authentication' },
        @{ File = '~/.config/containers/containers.conf'; Name = 'Container Runtime Config' },
        @{ File = '~/.config/containers/registries.conf'; Name = 'Registry Configuration' },
        @{ File = '~/.config/containers/policy.json'; Name = 'Image Signature Policy' },
        @{ File = '~/.config/containers/storage.conf'; Name = 'Storage Configuration' }
    )

    Write-Host "`n📋 Checking configuration files:" -ForegroundColor Cyan
    foreach ($test in $configTests) {
        $result = Invoke-InVM -Cmd "test -f $($test.File) && echo 'EXISTS' || echo 'MISSING'" -SSH $sshInfo
        $status = if ($result -match 'EXISTS') { '✅' } else { '❌' }
        Write-Host "   $status $($test.Name): $($test.File)" -ForegroundColor $(if ($result -match 'EXISTS') { 'Green' } else { 'Red' })
    }

    # Test Podman functionality
    Write-Host "`n🐳 Testing Podman functionality:" -ForegroundColor Cyan

    # Test registry authentication
    Write-Host "   🔐 Testing registry authentication..." -ForegroundColor White
    $authTest = Invoke-InVM -Cmd "podman login --get-login quay.io 2>/dev/null && echo 'AUTH_OK' || echo 'AUTH_FAILED'" -SSH $sshInfo
    $authStatus = if ($authTest -match 'AUTH_OK') { '✅' } else { '⚠️' }
    Write-Host "      $authStatus Registry authentication status" -ForegroundColor $(if ($authTest -match 'AUTH_OK') { 'Green' } else { 'Yellow' })

    # Test container pull
    Write-Host "   📥 Testing container image pull..." -ForegroundColor White
    $pullTest = Invoke-InVM -Cmd "podman pull alpine:latest >/dev/null 2>&1 && echo 'PULL_OK' || echo 'PULL_FAILED'" -SSH $sshInfo
    $pullStatus = if ($pullTest -match 'PULL_OK') { '✅' } else { '❌' }
    Write-Host "      $pullStatus Container image pull test" -ForegroundColor $(if ($pullTest -match 'PULL_OK') { 'Green' } else { 'Red' })

    # Test container run
    Write-Host "   🏃 Testing container execution..." -ForegroundColor White
    $runTest = Invoke-InVM -Cmd "podman run --rm alpine:latest echo 'CONTAINER_OK' 2>/dev/null || echo 'RUN_FAILED'" -SSH $sshInfo
    $runStatus = if ($runTest -match 'CONTAINER_OK') { '✅' } else { '❌' }
    Write-Host "      $runStatus Container execution test" -ForegroundColor $(if ($runTest -match 'CONTAINER_OK') { 'Green' } else { 'Red' })

    # Show Podman info
    Write-Host "`n📊 Podman system information:" -ForegroundColor Cyan

    # Get configuration file paths
    Write-Host "   Config files:" -ForegroundColor White
    $configInfo = Invoke-InVM -Cmd "podman info --format json | jq -r '.host.configFiles[] // \"None found\"' 2>/dev/null || echo 'Could not query config files'" -SSH $sshInfo
    if ($configInfo -match "Could not query") {
        # Alternative approach if jq doesn't work properly
        $configInfo = Invoke-InVM -Cmd "find ~/.config/containers -type f -name '*.conf*' -o -name '*.json' 2>/dev/null || echo 'No config files found'" -SSH $sshInfo
    }
    Write-Host "      $configInfo" -ForegroundColor Gray

    # Get storage driver
    Write-Host "   Storage driver:" -ForegroundColor White
    $storageDriver = Invoke-InVM -Cmd "podman info --format '{{.Store.GraphDriverName}}' 2>/dev/null || echo 'Unknown'" -SSH $sshInfo
    Write-Host "      $storageDriver" -ForegroundColor Gray

    # Get registry info
    Write-Host "   Registry configuration:" -ForegroundColor White
    $registryInfo = Invoke-InVM -Cmd "podman info --format '{{range .Registries.Search}}{{.}}{{println}}{{end}}' 2>/dev/null || echo 'None found'" -SSH $sshInfo
    Write-Host "      $registryInfo" -ForegroundColor Gray

    # Get Podman version
    Write-Host "   Podman version:" -ForegroundColor White
    Invoke-InVM -Cmd "podman version | grep -E 'Version|API' || echo 'Version info unavailable'" -SSH $sshInfo

    Write-Host "`n🎉 Configuration test completed!" -ForegroundColor Green

} catch {
    Write-Error "Failed to test configuration: $($_.Exception.Message)"
    exit 1
}

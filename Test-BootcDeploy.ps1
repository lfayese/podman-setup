# Test-BootcDeploy.ps1
# This script tests the bootc image deployment without rerunning the entire setup

[CmdletBinding()]
param(
    [string]$MachineName = 'podman-machine-default',
    [switch]$ForceRebuild
)

# Import ContainerSetup.ps1 as a module to access its functions
$containerSetupPath = Join-Path $PSScriptRoot 'ContainerSetup.ps1'
if (-not (Test-Path $containerSetupPath)) {
    Write-Error "ContainerSetup.ps1 not found at: $containerSetupPath"
    exit 1
}

# Load functions from ContainerSetup.ps1
. $containerSetupPath

Write-Host "Testing bootc image deployment on $MachineName" -ForegroundColor Cyan

# Get SSH connection info for the VM
Write-Host "Retrieving SSH connection info..." -ForegroundColor Cyan
$sshInfo = Get-SSHInfo -Name $MachineName

# Check if the VM is running
Write-Host "Checking if VM is running..." -ForegroundColor Cyan
$vmStatus = & podman machine info $MachineName
if (-not $vmStatus) {
    Write-Error "VM $MachineName not found or not running. Please start it first."
    exit 1
}

# Define container files path
$containerFilesPath = Join-Path $PSScriptRoot 'containers'

# If forced rebuild, remove existing image
if ($ForceRebuild) {
    Write-Host "Force rebuild requested, removing existing image..." -ForegroundColor Yellow
    $removeCmd = "podman rmi -f localhost/bootcdev-image 2>/dev/null || true"
    Invoke-InVM -Cmd $removeCmd -SSH $sshInfo
}

# Deploy and test bootc image
try {
    Write-Host "Deploying bootc image..." -ForegroundColor Cyan
    Deploy-BootcImage -SSH $sshInfo -ContainerFilesPath $containerFilesPath

    Write-Host "Testing bootc image..." -ForegroundColor Cyan
    $testResults = Test-BootcImage -SSH $sshInfo -Detailed

    # Display results
    Write-Host "`nTest Results:" -ForegroundColor Cyan
    Write-Host "  Image Exists:     $($testResults.ImageExists)" -ForegroundColor $(if ($testResults.ImageExists) { 'Green' } else { 'Red' })
    Write-Host "  Can Start:        $($testResults.CanStart)" -ForegroundColor $(if ($testResults.CanStart) { 'Green' } else { 'Red' })
    Write-Host "  Systemd Running:  $($testResults.SystemdRunning)" -ForegroundColor $(if ($testResults.SystemdRunning) { 'Green' } else { 'Red' })
    Write-Host "  Docker Running:   $($testResults.DockerRunning)" -ForegroundColor $(if ($testResults.DockerRunning) { 'Green' } else { 'Red' })
    Write-Host "  SSH Available:    $($testResults.SSHAccessible)" -ForegroundColor $(if ($testResults.SSHAccessible) { 'Green' } else { 'Red' })

    # Overall status
    $success = $testResults.ImageExists -and $testResults.CanStart
    if ($success) {
        Write-Host "`n✅ bootc image deployment and testing completed successfully" -ForegroundColor Green
        Write-Host "`nTo run the bootc container:" -ForegroundColor Cyan
        Write-Host "  podman machine ssh $MachineName '~/container-files/run-container.sh'" -ForegroundColor Gray
    } else {
        Write-Host "`n⚠️ bootc image deployment or testing encountered issues" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "❌ Error during bootc image deployment: $_" -ForegroundColor Red
    exit 1
}

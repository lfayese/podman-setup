#
# Script to build and run a container using configuration files from the current directory
# Rather than using hardcoded paths, this script uses the script's directory for all configs
#

# Define paths and variables
$ScriptDir = $PSScriptRoot  # Current script directory (containers folder)
$DataDir = Join-Path $env:TEMP "podman-containers-data"  # Use temp folder for data
$ImageName = "localhost/bootcdev-image"
$ContainerfilePath = $ScriptDir  # Use the containers folder where bootcdev.containerfile is located

# Create data directory if it doesn't exist
if (!(Test-Path -Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    Write-Output "Created data directory at $DataDir"
}

# Check for required files
$requiredFiles = @(
    "auth.json", 
    "containers.conf", 
    "policy.json", 
    "registries.conf", 
    "storage.conf", 
    "bootcdev.containerfile"
)
$missingFiles = @()

foreach ($file in $requiredFiles) {
    $filePath = Join-Path $ScriptDir $file
    if (!(Test-Path -Path $filePath)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Error "Missing required files in $ScriptDir`: $($missingFiles -join ', ')"
    Write-Output "Please ensure all configuration files are present before running this script."
    exit 1
}

# Check if image exists
$imageExists = podman images --format "{{.Repository}}" | Where-Object { $_ -eq $ImageName }

# Build image if not found
if (-not $imageExists) {
    $containerfilePath = Join-Path $ScriptDir "bootcdev.containerfile"
    Write-Output "Image '$ImageName' not found. Building from $containerfilePath..."
    podman build -t $ImageName -f $containerfilePath $ContainerfilePath
}

# Run the container
Write-Output "Starting bootc container from $ImageName..."
$containerId = podman run -d --name bootcdev `
  --privileged `
  --systemd always `
  -v "$(Join-Path $ScriptDir 'auth.json'):/usr/lib/container-auth.json:ro" `
  -v "$(Join-Path $ScriptDir 'containers.conf'):/etc/containers/containers.conf:ro" `
  -v "$(Join-Path $ScriptDir 'policy.json'):/etc/containers/policy.json:ro" `
  -v "$(Join-Path $ScriptDir 'registries.conf'):/etc/containers/registries.conf:ro" `
  -v "$(Join-Path $ScriptDir 'storage.conf'):/etc/containers/storage.conf:ro" `
  -v "${DataDir}:/var/lib/myapp" `
  -p 2222:22 `
  -p 8080:80 `
  -p 8443:443 `
  $ImageName

if ($containerId) {
    Write-Output "Container started with ID: $containerId"
    Write-Output "Access SSH on port 2222, HTTP on 8080, and HTTPS on 8443"
    Write-Output "To stop: podman stop bootcdev"
    Write-Output "To remove: podman rm bootcdev"
} else {
    Write-Error "Failed to start the container. Check if all required configuration files exist in the script directory."
    Write-Output "Required files: auth.json, containers.conf, policy.json, registries.conf, storage.conf, bootcdev.containerfile"
}

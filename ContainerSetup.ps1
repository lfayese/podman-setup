
<#
.SYNOPSIS
Sets up complete container environment for Windows 11 with Podman VM and Windows container tools.

.DESCRIPTION
Creates integrated container development environment with Podman VM (Linux/Windows containers) and
Windows native container tools (containerd, CNI, nerdctl, BuildKit). Features automatic setup with
certificate configuration and SSH access.

.EXAMPLE
# Setup with default settings
.\ContainerSetup.ps1

.EXAMPLE
# Setup only Podman VM with custom resources
.\ContainerSetup.ps1 -VMCpus 4 -VMMemoryMB 4096 -VMDiskSizeGB 60 -SetupWindowsTools $false

.EXAMPLE
# Setup only Windows container tools
.\ContainerSetup.ps1 -SetupPodmanVM $false -SetupWindowsTools $true

.EXAMPLE
# Full setup with custom certificate paths
.\ContainerSetup.ps1 -CertificatePath "C:\certs\ZscalerRoot.crt" -GitCABundlePath "C:\certs\git-ca.pem"
#>

[CmdletBinding()]
Param(
    # Podman VM parameters
    [string]$MachineName = 'podman-machine-default',
    [string]$CertificatePath = "$env:USERPROFILE\certs\ZscalerRootCertificate-2048-SHA256.crt",
    [string]$GitCABundlePath = "$env:USERPROFILE\certs\.git-ca-bundle.pem",
    [string]$BashrcPath = "C:\Tools\podman-setup\.bashrc",
    [int]$VMCpus = 2,
    [int]$VMMemoryMB = 4096,
    [int]$VMDiskSizeGB = 110,
    [bool]$IsRootful = $true,

    # Windows container tools parameters
    [Parameter()]
    [string]$SSHPublicKey,

    # Setup control flags
    [bool]$SetupPodmanVM = $true,
    [bool]$SetupWindowsTools = $true,
    [bool]$DeployBootcImage = $true,

    # Common parameters
    [int]$MaxRetries = 3,
    [int]$RetryDelaySeconds = 5
)

# Global logfile
$global:LogFile = Join-Path $env:TEMP ("container-setup-{0:yyyyMMdd-HHmmss}-{1}.log" -f (Get-Date), ([guid]::NewGuid()))

# Global script variables
### Remove duplicate global script variables
$script:MaxRetries = 3
$script:RetryDelaySeconds = 5
$script:DevRoot = 'C:\devtools'
$script:ContainerdVersion = '2.1.0'
$script:Arch = 'amd64'
$script:CniPluginVersion = '1.7.1'
$script:NerdctlVersion = '2.1.1'
$script:CriToolsVersion = '1.33.0'
# Ensure script variables for retries are initialized at the top level for later use
if (-not $script:MaxRetries)       { $script:MaxRetries = $MaxRetries }
if (-not $script:RetryDelaySeconds){ $script:RetryDelaySeconds = $RetryDelaySeconds }
if (-not $script:DevRoot)          { $script:DevRoot = 'C:\devtools' } # Used by downline functions

#--- LOGGING & UTILITIES -----------------------------------------------------
function Write-Log {
    [CmdletBinding()] Param(
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS')][string]$Level,
        [string]$Message
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    $line | Out-File -FilePath $global:LogFile -Append -Encoding UTF8
    switch ($Level) {
        'INFO'    { Write-Host $line -ForegroundColor Cyan }
        'WARNING' { Write-Host $line -ForegroundColor Yellow }
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
    }
}

function Write-InformationLog {
    [CmdletBinding()]
    param([string]$Message)
    Write-Log -Level INFO -Message $Message
}

function Invoke-WithRetry {
    [CmdletBinding()] Param(
        [scriptblock]$ScriptBlock,
        [string]$ActionName = 'Operation',
        [int]$MaxRetries = 3,
        [int]$DelaySeconds = 5,
        [object[]]$ArgumentList
    )

    # Use script variables if not provided explicitly
    if (-not $MaxRetries -or $MaxRetries -eq 0) { $MaxRetries = $script:MaxRetries }
    if (-not $DelaySeconds -or $DelaySeconds -eq 0) { $DelaySeconds = $script:RetryDelaySeconds }

    for ($i=1; $i -le $MaxRetries; $i++) {
        try {
            Write-Log -Level INFO -Message "$ActionName (Attempt $i/$MaxRetries)"
            return & $ScriptBlock @ArgumentList
        } catch {
            if ($i -eq $MaxRetries) {
                Write-Log -Level ERROR -Message "$ActionName failed: $_"
                throw
            }
            Write-Log -Level WARNING -Message "$ActionName failed, retrying in $DelaySeconds seconds: $_"
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function Wait-ForSSHReady {
  [CmdletBinding()]
  param(
      [Parameter(Mandatory)][string]$MachineName,
      [int]$MaxWaitSeconds = 180,
      [int]$CheckInterval = 10
  )
  Write-Log -Level INFO -Message "Waiting for SSH to be ready on machine: $MachineName"
  $elapsed = 0
  while ($elapsed -lt $MaxWaitSeconds) {
      try {
          Write-Log -Level INFO -Message "Testing SSH connection via podman machine ssh..."
          $result = & podman machine ssh $MachineName "echo 'SSH_READY'" 2>&1
          if ($LASTEXITCODE -eq 0 -and $result -match "SSH_READY") {
              Write-Log -Level SUCCESS -Message "SSH is ready via podman machine ssh"
              return $true
          }
      }
      catch {
          Write-Log -Level INFO -Message "SSH not ready yet: $_"
      }
      Write-Log -Level INFO -Message "Waiting for SSH... ($elapsed/$MaxWaitSeconds seconds)"
      Start-Sleep -Seconds $CheckInterval
      $elapsed += $CheckInterval
  }
  Write-Log -Level ERROR -Message "SSH not ready after $MaxWaitSeconds seconds"
  return $false
}

function Add-ToPath {
    [CmdletBinding()] Param([Parameter(Mandatory)][string]$Entry)
    $mp = [Environment]::GetEnvironmentVariable('Path','Machine')
    if ($mp.Split(';') -notcontains $Entry) {
        [Environment]::SetEnvironmentVariable('Path', "$mp;$Entry", 'Machine')
        Write-Log -Level INFO -Message "Injected $Entry into Machine PATH."
    }
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
}

function Copy-ToVM {
    [CmdletBinding()] Param(
        [Parameter(Mandatory)][string]$Src,
        [Parameter(Mandatory)][string]$Dest,
        [Parameter(Mandatory)][hashtable]$SSH
    )
    # Wait for SSH to be ready
    if (-not (Wait-ForSSHReady -MachineName $SSH.MachineName)) {
        throw "SSH connection not ready. Cannot copy files to VM."
    }
    # Try podman machine cp first (most reliable method)
    try {
        Write-Log -Level INFO -Message "Copying file using podman machine cp: $Src -> $Dest"
        & podman machine cp $Src "$($SSH.MachineName):$Dest" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Level SUCCESS -Message "Successfully copied file using podman machine cp"
            return
        } else {
            Write-Log -Level WARNING -Message "podman machine cp failed with exit code $LASTEXITCODE, trying alternative method"
        }
    } catch {
        Write-Log -Level WARNING -Message "podman machine cp failed: $_"
    }
    # If podman machine cp fails, try using SSH directly through podman machine ssh
    try {
        Write-Log -Level INFO -Message "Attempting file copy via podman machine ssh with base64 encoding"
        $fileContent = Get-Content -Path $Src -Raw -Encoding UTF8
        $base64Content = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($fileContent))
        $transferCmd = "echo '$base64Content' | base64 -d > '$Dest'"
        & podman machine ssh $SSH.MachineName $transferCmd
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Level SUCCESS -Message "Successfully copied file via SSH base64 transfer"
            return
        } else {
            throw "SSH base64 transfer failed with exit code $LASTEXITCODE"
        }
    }
    catch {
        Write-Log -Level ERROR -Message "All file copy methods failed: $_"
        throw "Failed to copy file to VM: $_"
    }
}

function Invoke-InVM {
    [CmdletBinding()] Param(
        [Parameter(Mandatory)][string]$Cmd,
        [Parameter(Mandatory)][hashtable]$SSH
    )
    # Wait for SSH to be ready
    if (-not (Wait-ForSSHReady -MachineName $SSH.MachineName)) {
        throw "SSH connection not ready. Cannot execute commands in VM."
    }
    try {
        Write-Log -Level INFO -Message "Executing in VM: $Cmd"
        $result = & podman machine ssh $SSH.MachineName "$Cmd" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code ${LASTEXITCODE}: ${result}"
        }
        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "VM command execution failed: $_"
        throw
    }
        $result = & $sshPath @sshArgs 2>&1

        if ($LASTEXITCODE -ne 0) {
            throw "SSH command failed with exit code $LASTEXITCODE $result"
        }

        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "SSH command failed: $($_.Exception.Message)"
        throw @"
SSH connection failed. Please check:
1. Is the Podman VM running? (podman machine list)
2. Is SSH service running in the VM? (podman machine ssh $($SSH.MachineName) 'systemctl status sshd')
3. Is the SSH key path correct? ($($SSH.KeyPath))
4. Is the SSH port accessible? (Test-NetConnection 127.0.0.1 -Port $($SSH.Port))
"@
    }

function Invoke-DownloadAndExtract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][ValidateSet('tar','zip')][string]$Format
    )
    # Ensure DevRoot is initialized
    if (-not $script:DevRoot) {
        $script:DevRoot = 'C:\devtools'
    }
    $file = Join-Path $script:DevRoot ([IO.Path]::GetFileName($Url))
    Write-Log -Level INFO -Message "Downloading $Url"
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $file
    Write-Log -Level INFO -Message "Extracting to $Destination"
    if ($Format -eq 'zip') {
        Expand-Archive -Path $file -DestinationPath $Destination -Force
    } else {
        tar.exe xvf $file -C $Destination
    }
}

#--- SELF-ELEVATION ----------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevation required → relaunching as Administrator…" -ForegroundColor Yellow
    $psi = [System.Diagnostics.ProcessStartInfo]::new(
        'pwsh', "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    )
    $psi.Verb = 'runas'
    try { [System.Diagnostics.Process]::Start($psi) } catch {
        Write-Host "Elevation aborted. Please run as Admin." -ForegroundColor Red
    }
    exit
}

Write-Log -Level INFO -Message "Container environment setup started"

#--- HELPER FUNCTIONS -------------------------------------------------------
function Get-PodmanDesktopPublicKey {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$UpdateContainerFiles = $false,

        [Parameter()]
        [string]$ContainersDir = (Join-Path $PSScriptRoot 'containers')
    )

    $podmanPubKeyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine.pub"

    if (-not (Test-Path $podmanPubKeyPath)) {
        Write-Log -Level ERROR -Message "Podman Desktop SSH public key not found at: $podmanPubKeyPath"
        throw "SSH public key not found. Please ensure Podman Desktop is properly installed."
    }

    $publicKeyContent = Get-Content $podmanPubKeyPath -Raw
    $publicKeyContent = $publicKeyContent.Trim()

    Write-Log -Level INFO -Message "Successfully read Podman Desktop public key"

    # If requested, update container configuration files with the SSH key
    if ($UpdateContainerFiles) {
        # Create containers directory if it doesn't exist
        if (-not (Test-Path $ContainersDir)) {
            New-Item -Path $ContainersDir -ItemType Directory -Force | Out-Null
            Write-Log -Level INFO -Message "Created containers directory at $ContainersDir"
        }

        # Update config file
        $configPath = Join-Path $ContainersDir 'config'
        try {
            # If file exists, read it first
            if (Test-Path $configPath) {
                $configContent = Get-Content $configPath -Raw
                # Only add the key if it doesn't already contain it
                if ($configContent -notmatch [regex]::Escape($publicKeyContent)) {
                    Add-Content -Path $configPath -Value "`n# Podman Desktop SSH Public Key`n$publicKeyContent`n"
                    Write-Log -Level INFO -Message "Added Podman Desktop public key to config file"
                }
            } else {
                # Create new config file with the key
                Set-Content -Path $configPath -Value "# Podman Desktop SSH Public Key`n$publicKeyContent`n"
                Write-Log -Level INFO -Message "Created config file with Podman Desktop public key"
            }
        } catch {
            Write-Log -Level WARNING -Message "Failed to update config file: $_"
        }

        # Update podman-win file
        $podmanWinPath = Join-Path $ContainersDir 'podman-win'
        try {
            # If file exists, read it first
            if (Test-Path $podmanWinPath) {
                $podmanWinContent = Get-Content $podmanWinPath -Raw
                # Only add the key if it doesn't already contain it
                if ($podmanWinContent -notmatch [regex]::Escape($publicKeyContent)) {
                    Add-Content -Path $podmanWinPath -Value "`n# Podman Desktop SSH Public Key`n$publicKeyContent`n"
                    Write-Log -Level INFO -Message "Added Podman Desktop public key to podman-win file"
                }
            } else {
                # Create new podman-win file with the key
                Set-Content -Path $podmanWinPath -Value "# Podman Desktop SSH Public Key`n$publicKeyContent`n"
                Write-Log -Level INFO -Message "Created podman-win file with Podman Desktop public key"
            }
        } catch {
            Write-Log -Level WARNING -Message "Failed to update podman-win file: $_"
        }
    }

    return $publicKeyContent
}

#--- PODMAN VM SETUP FUNCTIONS -----------------------------------------------
function Test-PodmanPrerequisite {
    # Check if Podman is installed and verify version compatibility
    try {
        $podmanVersion = & podman --version
        Write-Log -Level INFO -Message "Found $podmanVersion"

        # Extract version number from output (e.g., "podman version 4.7.2" -> "4.7.2")
        if ($podmanVersion -match 'podman version (\d+\.\d+\.\d+)') {
            $versionNumber = $Matches[1]
            $versionParts = $versionNumber.Split('.')
            $majorVersion = [int]$versionParts[0]

            # Warn about cgroups-v2 requirement for Podman v5+
            if ($majorVersion -ge 5) {
                Write-Log -Level WARNING -Message "Podman v5+ detected. Will configure with cgroups-v2 support."
            }

            # Check for minimum required version
            if ($majorVersion -lt 4) {
                Write-Log -Level WARNING -Message "Podman version $versionNumber may have limited compatibility. Version 4.0.0 or higher is recommended."
            }
        } else {
            Write-Log -Level WARNING -Message "Could not parse Podman version from: $podmanVersion"
        }
    } catch {
        throw "Podman not found. Please install Podman for Windows first."
    }

    # Check if required certificates exist with helpful error messages
    if (-not (Test-Path $CertificatePath)) {
        $defaultCertPath = "$env:USERPROFILE\certs\ZscalerRootCertificate-2048-SHA256.crt"
        $message = @"
Certificate not found at: $CertificatePath

Please ensure you have the required certificate in place or specify a different path.
You can:
1. Place the certificate at: $defaultCertPath
2. Specify a different path using the -CertificatePath parameter
3. If you don't need a custom certificate, create an empty file at that path (not recommended for production).
"@
        Write-Log -Level ERROR -Message $message
        throw $message
    }

    if (-not (Test-Path $GitCABundlePath)) {
        $defaultBundlePath = "$env:USERPROFILE\certs\.git-ca-bundle.pem"
        $message = @"
Git CA bundle not found at: $GitCABundlePath

Please ensure you have the required CA bundle in place or specify a different path.
You can:
1. Place the bundle at: $defaultBundlePath
2. Specify a different path using the -GitCABundlePath parameter
3. If you don't need a custom git CA bundle, create an empty file at that path (not recommended for production).
"@
        Write-Log -Level ERROR -Message $message
        throw $message
    }

    if (-not (Test-Path $BashrcPath)) {
        $defaultBashrcPath = "C:\Tools\podman-setup\.bashrc"
        $message = @"
Bashrc file not found at: $BashrcPath

Please ensure you have a custom .bashrc file or specify a different path.
You can:
1. Place a .bashrc file at: $defaultBashrcPath
2. Specify a different path using the -BashrcPath parameter
3. Use any existing .bashrc file from your system
"@
        Write-Log -Level ERROR -Message $message
        throw $message
    }

    # Check Windows features
    $requiredFeatures = @('Microsoft-Hyper-V', 'Containers')
    $missingFeatures = @()

    foreach ($feature in $requiredFeatures) {
        $state = (Get-WindowsOptionalFeature -Online -FeatureName $feature).State
        if ($state -ne 'Enabled') {
            $missingFeatures += $feature
        }
    }

    if ($missingFeatures.Count -gt 0) {
        throw "Missing required Windows features: $($missingFeatures -join ', '). Please enable them and restart."
    }

    Write-Log -Level SUCCESS -Message "All prerequisites validated"
}

function Remove-ExistingMachine {
    [CmdletBinding()]
    param([string]$Name)

    Write-Log -Level INFO -Message "Checking for existing Podman machine: $Name"
    $existingVM = & podman machine list --format json | ConvertFrom-Json | Where-Object Name -eq $Name

    if ($existingVM) {
        Write-Log -Level INFO -Message "Found existing machine, stopping and removing..."
        & podman machine stop $Name
        & podman machine rm -f $Name
        Write-Log -Level SUCCESS -Message "Removed existing machine: $Name"
    } else {
        Write-Log -Level INFO -Message "No existing machine found with name: $Name"
    }
}

function Initialize-NewMachine {
    [CmdletBinding()]
    param(
        [string]$Name,
        [int]$Cpus,
        [int]$MemoryMB,
        [int]$DiskGB,
        [bool]$Rootful = $true  # Explicitly default to rootful here as well
    )

    # Always use --rootful flag when $Rootful is true (which it is by default)
    $rootfulFlag = if ($Rootful) { "--rootful" } else { "" }

    Write-Log -Level INFO -Message "Creating new Podman machine: $Name"
    Write-Log -Level INFO -Message "Specs: CPUs=$Cpus, Memory=${MemoryMB}MB, Disk=${DiskGB}GB, Rootful=$Rootful"

    # Create the Podman machine without the unsupported --cgroup-manager flag
    $cmd = "podman machine init $Name --cpus $Cpus --memory $MemoryMB --disk-size $DiskGB $rootfulFlag"
    Invoke-Expression $cmd

    Write-Log -Level INFO -Message "Starting Podman machine: $Name"
    & podman machine start $Name

    # Verify the machine is running properly before proceeding
    Write-Log -Level INFO -Message "Verifying machine is running..."
    try {
        # Check if the machine exists and is running
        $machineStatus = & podman machine list --format json | ConvertFrom-Json | Where-Object Name -eq $Name

        if (-not $machineStatus) {
            throw "Machine '$Name' was not created properly"
        }

        if ($machineStatus.Running -ne $true) {
            Write-Log -Level WARNING -Message "Machine is not running. Attempting to start it again."
            & podman machine start $Name

            # Verify it started
            $machineStatus = & podman machine list --format json | ConvertFrom-Json | Where-Object Name -eq $Name
            if ($machineStatus.Running -ne $true) {
                throw "Failed to start machine '$Name'"
            }
        }

        # Configure cgroups-v2 through podman machine ssh instead
        $cgroupCheck = & podman machine ssh $Name "grep -s cgroup2 /proc/filesystems || echo 'cgroups-v2 not enabled'"
        if ($cgroupCheck -match "cgroups-v2 not enabled") {
            Write-Log -Level WARNING -Message "cgroups-v2 might not be properly enabled. Some features may not work correctly."
        } else {
            Write-Log -Level SUCCESS -Message "cgroups-v2 properly configured."
        }
    } catch {
        Write-Log -Level WARNING -Message "Machine verification failed: $_"
        throw "Failed to initialize or verify Podman machine: $_"
    }

    Write-Log -Level SUCCESS -Message "Podman machine initialized and started: $Name"
}

function Get-SSHInfo {
    [CmdletBinding()]
    param([string]$Name)

    Write-Log -Level INFO -Message "Retrieving SSH connection info for: $Name"

    # First verify the VM exists and is running
    $machineExists = & podman machine list --format json | ConvertFrom-Json | Where-Object Name -eq $Name
    if (-not $machineExists) {
        throw "Cannot get SSH info: machine '$Name' does not exist"
    }

    if ($machineExists.Running -ne $true) {
        throw "Cannot get SSH info: machine '$Name' exists but is not running"
    }

    # Get the machine information
    $machineInfo = & podman machine inspect $Name | ConvertFrom-Json

    # Check if the machine has a valid SSH Identity Path
    $machineSpecificKeyExists = $false
    if ($machineInfo.SSHConfig -and $machineInfo.SSHConfig.IdentityPath -and (Test-Path $machineInfo.SSHConfig.IdentityPath)) {
        $machineSpecificKeyExists = $true
        Write-Log -Level INFO -Message "Using machine-specific SSH key: $($machineInfo.SSHConfig.IdentityPath)"
    }

    # Fallback to Podman Desktop keys if machine-specific key doesn't exist
    $podmanKeyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine"
    $podmanPubKeyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine.pub"

    # Determine which key to use - using if/else for better null handling than ternary operator
    if ($machineSpecificKeyExists) {
        $keyPath = $machineInfo.SSHConfig.IdentityPath
        $pubKeyPath = "$($machineInfo.SSHConfig.IdentityPath).pub"
    } else {
        $keyPath = $podmanKeyPath
        $pubKeyPath = $podmanPubKeyPath
    }

    # Verify the selected SSH key exists
    if (-not $keyPath -or -not (Test-Path $keyPath)) {
        Write-Log -Level ERROR -Message "SSH private key not found at: $keyPath"

        # Try to find an alternative SSH key
        $alternativePath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine"
        if (Test-Path $alternativePath) {
            Write-Log -Level WARNING -Message "Using alternative SSH key at: $alternativePath"
            $keyPath = $alternativePath
            $pubKeyPath = "$alternativePath.pub"
        } else {
            throw "SSH private key not found. Please ensure Podman is properly installed."
        }
    }

    # Determine user: prefer SSHConfig.User, fallback to 'root' or 'user' based on Rootful
    $user = $null
    if ($machineInfo.SSHConfig -and $machineInfo.SSHConfig.User) {
        $user = $machineInfo.SSHConfig.User
    } elseif ($machineInfo.Rootful -eq $true) {
        $user = 'root'
    } else {
        $user = 'user'
    }

    # Create SSH info hash with null checks for all properties
    $sshInfo = @{
        User = $user
        Port = if ($machineInfo.SSHConfig -and $machineInfo.SSHConfig.Port) { $machineInfo.SSHConfig.Port } else { "22" }
        KeyPath = $keyPath
        PubKeyPath = $pubKeyPath
        SocketPath = if ($machineInfo.ConnectionInfo -and $machineInfo.ConnectionInfo.PodmanSocket) { $machineInfo.ConnectionInfo.PodmanSocket } else { $null }
        UsingMachineKey = $machineSpecificKeyExists
        MachineName = $Name
    }

    Write-Log -Level INFO -Message "SSH Info: User=$($sshInfo.User), Port=$($sshInfo.Port), KeyPath=$($sshInfo.KeyPath), Socket=$($sshInfo.SocketPath)"

    return $sshInfo
}

function Install-WindowsContainerSupport {
    [CmdletBinding()]
    param([string]$Version = 'latest')

    Write-Log -Level INFO -Message "Testing Windows container support"

    # Verify podman machine connection first
    Write-Log -Level INFO -Message "Verifying podman machine connection"
    $podmanInfo = & podman info --format json | ConvertFrom-Json
    if (-not $podmanInfo.host.ociRuntime.name) {
        throw "Podman is not properly connected to the VM"
    }

    # Set platform for Windows containers and run test
    Write-Log -Level INFO -Message "Testing Windows container with explicit platform"
    $env:DOCKER_DEFAULT_PLATFORM = 'windows'
    $testCmd = "podman run --platform windows/amd64 --rm mcr.microsoft.com/windows/nanoserver:ltsc2022 cmd /c echo Windows containers are working!"

    try {
        $result = Invoke-Expression $testCmd
        if ($result -match "Windows containers are working!") {
            Write-Log -Level SUCCESS -Message "Windows container test successful"
        } elseif ($result -match "no matching entries in passwd file" -or $result -match "unable to find user ContainerUser") {
            Write-Log -Level WARNING -Message "Known Podman/Windows issue: $result. Skipping test."
        } else {
            Write-Log -Level WARNING -Message "Windows container test failed with unexpected output: $result"
            # Do not throw, just warn and continue
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Windows container test failed with exception: $($_.Exception.Message)"
        # Do not throw, just warn and continue
    }
}

function Deploy-BootcImage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$SSH,

        [Parameter(Mandatory)]
        [string]$ContainerFilesPath,

        [string]$ImageName = "localhost/bootcdev-image",

        [string]$ContainerFileName = "bootcdev.containerfile",

        [int]$MaxRetries = $script:MaxRetries,

        [int]$RetryDelaySeconds = $script:RetryDelaySeconds
    )

    Write-Log -Level INFO -Message "Starting bootc image deployment"

    # Verify container files path exists
    if (-not (Test-Path $ContainerFilesPath)) {
        Write-Log -Level ERROR -Message "Container files directory not found: $ContainerFilesPath"
        throw "Container files directory not found: $ContainerFilesPath"
    }

    # Verify containerfile exists
    $containerfilePath = Join-Path $ContainerFilesPath $ContainerFileName
    if (-not (Test-Path $containerfilePath)) {
        Write-Log -Level ERROR -Message "Containerfile not found at: $containerfilePath"
        throw "Containerfile not found: $containerfilePath"
    }

    # Create target directory in VM
    try {
        Write-Log -Level INFO -Message "Creating container files directory in VM"
        Invoke-WithRetry -ScriptBlock {
            Invoke-InVM -Cmd "mkdir -p ~/container-files" -SSH $SSH
        } -ActionName "Create container-files directory in VM" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to create container-files directory in VM: $_"
        throw
    }

    # Define configuration files to copy
    $filesToCopy = @(
        @{ Name = $ContainerFileName; Required = $true },
        @{ Name = "caddy.container"; Required = $false },
        @{ Name = "containers-auth.conf"; Required = $false },
        @{ Name = "containers.conf"; Required = $true },
        @{ Name = "storage.conf"; Required = $true },
        @{ Name = "auth.json"; Required = $true },
        @{ Name = "policy.json"; Required = $true },
        @{ Name = "registries.conf"; Required = $true },
        @{ Name = "run-container.sh"; Required = $false },
        @{ Name = "run-container.ps1"; Required = $false }
    )

    # Copy each file to VM
    foreach ($file in $filesToCopy) {
        $sourcePath = Join-Path $ContainerFilesPath $file.Name
        if (Test-Path $sourcePath) {
            Write-Log -Level INFO -Message "Copying $($file.Name) to VM"
            try {
                Invoke-WithRetry -ScriptBlock {
                    Copy-ToVM -Src $sourcePath -Dest "~/container-files/$($file.Name)" -SSH $SSH
                } -ActionName "Copy $($file.Name) to VM" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds
            }
            catch {
                $errorMsg = "Failed to copy $($file.Name) to VM: $_"
                if ($file.Required) {
                    Write-Log -Level ERROR -Message $errorMsg
                    throw $errorMsg
                } else {
                    Write-Log -Level WARNING -Message "$errorMsg - Continuing as this file is optional"
                }
            }
        } else {
            $missingMsg = "File not found: $sourcePath"
            if ($file.Required) {
                Write-Log -Level ERROR -Message $missingMsg
                throw $missingMsg
            } else {
                Write-Log -Level WARNING -Message "$missingMsg - Continuing as this file is optional"
            }
        }
    }

    # Setup container configuration directories in VM
    try {
        Write-Log -Level INFO -Message "Setting up container configuration in VM"

        # Create config directory
        Invoke-WithRetry -ScriptBlock {
            Invoke-InVM -Cmd "mkdir -p ~/.config/containers" -SSH $SSH
        } -ActionName "Create containers config directory" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds

        # Copy configuration files to proper locations
        $configFiles = @("auth.json", "containers.conf", "storage.conf", "policy.json", "registries.conf")
        foreach ($file in $configFiles) {
            Invoke-WithRetry -ScriptBlock {
                Invoke-InVM -Cmd "cp ~/container-files/$file ~/.config/containers/" -SSH $SSH
            } -ActionName "Copy $file to containers config" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds
        }

        # Set permissions on auth.json
        Invoke-WithRetry -ScriptBlock {
            Invoke-InVM -Cmd "chmod 600 ~/.config/containers/auth.json" -SSH $SSH
        } -ActionName "Set permissions on auth.json" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to set up container configuration in VM: $_"
        throw
    }

    # Make run scripts executable
    try {
        if (Test-Path (Join-Path $ContainerFilesPath "run-container.sh")) {
            Write-Log -Level INFO -Message "Making run-container.sh executable"
            Invoke-WithRetry -ScriptBlock {
                Invoke-InVM -Cmd "chmod +x ~/container-files/run-container.sh" -SSH $SSH
            } -ActionName "Make run-container.sh executable" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Failed to make run-container.sh executable: $_ - Continuing anyway"
    }

    # Build bootc image
    try {
        Write-Log -Level INFO -Message "Building bootc image from containerfile"
        $buildResult = Invoke-WithRetry -ScriptBlock {
            Invoke-InVM -Cmd "cd ~/container-files && PODMAN_IGNORE_CGROUPSV1_WARNING=1 podman build -t $ImageName -f $ContainerFileName ." -SSH $SSH
        } -ActionName "Build bootc image" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds

        # Verify build success
        if ($buildResult -match "error" -or $buildResult -match "failed") {
            throw "Build output indicates failure: $buildResult"
        }

        # Create data directory for persistence
        Invoke-WithRetry -ScriptBlock {
            Invoke-InVM -Cmd "mkdir -p ~/.local/share/containers/storage/containers/data" -SSH $SSH
        } -ActionName "Create data directory" -MaxRetries $MaxRetries -DelaySeconds $RetryDelaySeconds
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to build bootc image: $_"
        throw
    }

    # Test the image
    try {
        Write-Log -Level INFO -Message "Testing bootc image"
        $testResult = Invoke-WithRetry -ScriptBlock {
            Invoke-InVM -Cmd "PODMAN_IGNORE_CGROUPSV1_WARNING=1 podman image exists $ImageName && echo 'IMAGE_EXISTS_SUCCESS'" -SSH $SSH
        } -ActionName "Test bootc image" -MaxRetries 1 -DelaySeconds 1

        if ($testResult -notmatch "IMAGE_EXISTS_SUCCESS") {
            throw "Image verification failed"
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Failed to verify bootc image: $_ - Image may not have built correctly"
    }

    Write-Log -Level SUCCESS -Message "bootc image deployment completed successfully"
    Write-Log -Level INFO -Message "To run the container, connect to the VM and execute: ~/container-files/run-container.sh"

    return $true
}

function Test-BootcImage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$SSH,

        [string]$ImageName = "localhost/bootcdev-image",

        [string]$ContainerName = "bootcdev-test",

        [switch]$Detailed
    )

    Write-Log -Level INFO -Message "Testing bootc image..."
    $results = @{
        ImageExists = $false
        CanStart = $false
        SSHAccessible = $false
        SystemdRunning = $false
        DockerRunning = $false
    }

    try {
        # Check if image exists
        $imageCheck = Invoke-InVM -Cmd "PODMAN_IGNORE_CGROUPSV1_WARNING=1 podman image exists $ImageName && echo 'IMAGE_EXISTS_SUCCESS' || echo 'IMAGE_NOT_FOUND'" -SSH $SSH
        $results.ImageExists = $imageCheck -match "IMAGE_EXISTS_SUCCESS"

        if (-not $results.ImageExists) {
            Write-Log -Level WARNING -Message "bootc image not found: $ImageName"
            return $results
        }

        Write-Log -Level INFO -Message "bootc image exists, testing container startup..."

        # Try to start container
        $startCmd = "PODMAN_IGNORE_CGROUPSV1_WARNING=1 podman run -d --name $ContainerName --privileged --systemd=always $ImageName && echo 'CONTAINER_START_SUCCESS' || echo 'CONTAINER_START_FAILED'"
        $startResult = Invoke-InVM -Cmd $startCmd -SSH $SSH
        $results.CanStart = $startResult -match "CONTAINER_START_SUCCESS"

        if (-not $results.CanStart) {
            Write-Log -Level WARNING -Message "Failed to start test container"
            return $results
        }

        Write-Log -Level INFO -Message "Container started, running tests..."

        if ($Detailed) {
            # Test for systemd
            $systemdTest = Invoke-InVM -Cmd "PODMAN_IGNORE_CGROUPSV1_WARNING=1 podman exec $ContainerName systemctl status && echo 'SYSTEMD_SUCCESS' || echo 'SYSTEMD_FAILED'" -SSH $SSH
            $results.SystemdRunning = $systemdTest -match "SYSTEMD_SUCCESS"

            # Test for docker service
            $dockerTest = Invoke-InVM -Cmd "PODMAN_IGNORE_CGROUPSV1_WARNING=1 podman exec $ContainerName systemctl status docker && echo 'DOCKER_SUCCESS' || echo 'DOCKER_FAILED'" -SSH $SSH
            $results.DockerRunning = $dockerTest -match "DOCKER_SUCCESS"

            # Test for SSH access
            $sshTest = Invoke-InVM -Cmd "PODMAN_IGNORE_CGROUPSV1_WARNING=1 podman exec $ContainerName systemctl status sshd && echo 'SSH_SUCCESS' || echo 'SSH_FAILED'" -SSH $SSH
            $results.SSHAccessible = $sshTest -match "SSH_SUCCESS"
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Error testing bootc image: $_"
    }
    finally {
        # Clean up test container
        try {
            Invoke-InVM -Cmd "PODMAN_IGNORE_CGROUPSV1_WARNING=1 podman rm -f $ContainerName 2>/dev/null || true" -SSH $SSH | Out-Null
        }
        catch {
            Write-Log -Level WARNING -Message "Failed to clean up test container: $_"
        }
    }

    # Log results
    if ($results.ImageExists -and $results.CanStart) {
        Write-Log -Level SUCCESS -Message "bootc image test passed: Image exists and container can start"
        if ($Detailed) {
            Write-Log -Level INFO -Message "Detailed test results:"
            Write-Log -Level INFO -Message " - Systemd running: $($results.SystemdRunning)"
            Write-Log -Level INFO -Message " - Docker service: $($results.DockerRunning)"
            Write-Log -Level INFO -Message " - SSH service: $($results.SSHAccessible)"
        }
    } else {
        Write-Log -Level WARNING -Message "bootc image test failed"
        Write-Log -Level WARNING -Message " - Image exists: $($results.ImageExists)"
        Write-Log -Level WARNING -Message " - Can start container: $($results.CanStart)"
    }

    return $results
}

#--- WINDOWS CONTAINER TOOLS FUNCTIONS ---------------------------------------
function Install-ContainerTools {
    [CmdletBinding()]
    param([string]$SSHPublicKey)

    # If no SSH public key provided, try to get it from Podman Desktop
    if (-not $SSHPublicKey) {
        Write-Log -Level INFO -Message "No SSH public key provided, reading from Podman Desktop"
        try {
            # Update this line to also write the key to container config files
            $SSHPublicKey = Get-PodmanDesktopPublicKey -UpdateContainerFiles $true
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to read Podman Desktop public key: $($_.Exception.Message)"
            throw "SSH public key is required for Windows container tools setup. Either provide -SSHPublicKey parameter or ensure Podman Desktop is installed."
        }
    }

    # Define or ensure global variables for Windows container tools
    if (-not $script:DevRoot) { $script:DevRoot = 'C:\devtools' }
    if (-not $script:ContainerdVersion) { $script:ContainerdVersion = '2.1.0' }
    if (-not $script:Arch) { $script:Arch = 'amd64' }
    if (-not $script:CniPluginVersion) { $script:CniPluginVersion = '1.7.1' }
    if (-not $script:NerdctlVersion) { $script:NerdctlVersion = '2.1.1' }
    if (-not $script:CriToolsVersion) { $script:CriToolsVersion = '1.33.0' }

    Write-Log -Level INFO -Message "Starting Windows container tools installation"

    # Environment preparation
    Write-Log -Level INFO -Message 'Enabling Containers and Hyper-V features'
    Enable-WindowsOptionalFeature -Online -FeatureName Containers,Microsoft-Hyper-V -All | Out-Null

    New-Item -Path $script:DevRoot -ItemType Directory -Force | Out-Null

    # Install containerd
    Install-Containerd

    # Install CNI plugins
    Install-CniPlugins

    # Install nerdctl & CRI-tools
    Install-ContainerCliTools

    # Install BuildKit
    Install-BuildKit

    # Configure OpenSSH
    Install-ConfigureOpenSSH -PublicKey $SSHPublicKey

    Write-Log -Level SUCCESS -Message 'Windows container tools setup complete'
}

function Install-Containerd {
    Write-Log -Level INFO -Message "Installing containerd v$ContainerdVersion"
    Stop-Service containerd -ErrorAction SilentlyContinue

    $cdPath = Join-Path $script:DevRoot 'containerd'
    New-Item -Path $cdPath -ItemType Directory -Force | Out-Null

    $cdUrl = "https://github.com/containerd/containerd/releases/download/v$ContainerdVersion/containerd-$ContainerdVersion-windows-$script:Arch.tar.gz"
    Invoke-DownloadAndExtract -Url $cdUrl -Destination $cdPath -Format tar

    Add-ToPath -Entry "$cdPath\bin"

    & "$cdPath\bin\containerd.exe" config default |
        Out-File "$cdPath\config.toml" -Encoding ascii
    Write-Log -Level INFO -Message 'Generated default config.toml (adjust as needed)'

    & "$cdPath\bin\containerd.exe" --register-service
    Start-Service containerd
    Write-Log -Level SUCCESS -Message 'containerd service started'
}

function Install-CniPlugins {
    Write-Log -Level INFO -Message "Installing CNI plugins v$CniPluginVersion"
    $cdPath = Join-Path $script:DevRoot 'containerd'
    $cniBin = Join-Path $cdPath 'cni\bin'
    $cniConf = Join-Path $cdPath 'cni\conf'
    New-Item -Path $cniBin,$cniConf -ItemType Directory -Force | Out-Null

    $cniUrl = "https://github.com/containernetworking/plugins/releases/download/v$CniPluginVersion/cni-plugins-windows-$script:Arch-v$CniPluginVersion.tgz"
    Invoke-DownloadAndExtract -Url $cniUrl -Destination $cniBin -Format tar

    $network = 'nat'
    $hnsNet = Get-HnsNetwork -ErrorAction SilentlyContinue | Where-Object Name -eq $network
    if (-not $hnsNet) {
        throw "HNS network '$network' not found ensure features enabled and rebooted."
    }

    $gateway = $hnsNet.Subnets[0].GatewayAddress
    $subnet = $hnsNet.Subnets[0].AddressPrefix
    $confJson = @{
        cniVersion = '0.4.0'
        name = $network
        type = 'nat'
        master = 'Ethernet'
        ipam = @{
            type = 'host-local'
            subnet = $subnet
            routes = @(@{ gateway = $gateway })
        }
        capabilities = @{
            portMappings = $true
            dns = $true
        }
    } | ConvertTo-Json -Depth 4

    $confFile = Join-Path $cniConf "0-containerd-nat.conf"
    $confJson | Set-Content -Path $confFile -Encoding ascii
    Write-Log -Level SUCCESS -Message "CNI config written to $confFile"

    return $confFile
}

function Install-ContainerCliTools {
    foreach ($tool in @(
        @{ Name = 'nerdctl'; Ver = $script:NerdctlVersion; Url = "https://github.com/containerd/nerdctl/releases/download/v$script:NerdctlVersion/nerdctl-$script:NerdctlVersion-windows-$script:Arch.tar.gz" },
        @{ Name = 'crictl'; Ver = $script:CriToolsVersion; Url = "https://github.com/kubernetes-sigs/cri-tools/releases/download/v$script:CriToolsVersion/crictl-v$script:CriToolsVersion-windows-$script:Arch.tar.gz" },
        @{ Name = 'critest'; Ver = $script:CriToolsVersion; Url = "https://github.com/kubernetes-sigs/cri-tools/releases/download/v$script:CriToolsVersion/critest-v$script:CriToolsVersion-windows-$script:Arch.tar.gz" }
    )) {
        Write-Log -Level INFO -Message "Installing $($tool.Name) v$($tool.Ver)"
        $dest = Join-Path $script:DevRoot $tool.Name
        New-Item -Path $dest -ItemType Directory -Force | Out-Null
        Invoke-DownloadAndExtract -Url $tool.Url -Destination $dest -Format tar
        Add-ToPath -Entry $dest
    }
}

function Install-BuildKit {
    Write-Log -Level INFO -Message 'Installing BuildKit'
    $bkApi = 'https://api.github.com/repos/moby/buildkit/releases/latest'
    $bkRelease = Invoke-RestMethod -Uri $bkApi -UseBasicParsing
    $bkTag = $bkRelease.tag_name
    if ($bkTag -like 'v*') { $bkTag = $bkTag.TrimStart('v') }
    $bkUrl = "https://github.com/moby/buildkit/releases/download/v$bkTag/buildkit-v$bkTag.windows-$script:Arch.tar.gz"
    $bkRoot = Join-Path $script:DevRoot 'buildkit'
    New-Item -Path $bkRoot -ItemType Directory -Force | Out-Null

    Invoke-DownloadAndExtract -Url $bkUrl -Destination $bkRoot -Format tar
    Add-ToPath -Entry $bkRoot

    $cdPath = Join-Path $script:DevRoot 'containerd'
    $cniBin = Join-Path $cdPath 'cni\bin'
    $cniConf = Join-Path $cdPath 'cni\conf'
    $confFile = Join-Path $cniConf "0-containerd-nat.conf"

    & "$bkRoot\buildkitd.exe" --register-service --service-name buildkitd `
        --containerd-cni-config-path="$confFile" `
        --containerd-cni-binary-dir="$cniBin"
    Set-Service -Name buildkitd -StartupType Automatic
    Start-Service buildkitd
    Write-Log -Level SUCCESS -Message 'buildkitd service started'
}

function Install-ConfigureOpenSSH {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PublicKey)

    Write-Log -Level INFO -Message 'Installing and configuring OpenSSH'
    Get-WindowsCapability -Online -Name OpenSSH.Server* | Add-WindowsCapability -Online
    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd

    # Configure authorized keys
    $authFile = 'C:\ProgramData\ssh\administrators_authorized_keys'
    New-Item -Path $authFile -ItemType File -Force | Out-Null
    Set-Content -Path $authFile -Value $PublicKey -Encoding ascii
    $acl = Get-Acl $authFile
    $acl.SetAccessRuleProtection($true,$false)
    $rules = @(
        New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','Allow'),
        New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','Allow')
    )
    $rules | ForEach-Object { $acl.AddAccessRule($_) }
    $acl | Set-Acl

    # Set PowerShell as default shell if available
    if (Test-Path 'C:\Program Files\PowerShell\7\pwsh.exe') {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
            -PropertyType String -Value 'C:\Program Files\PowerShell\7\pwsh.exe' -Force
    }

    Write-Log -Level SUCCESS -Message 'SSH configured successfully'
}

#--- MAIN WORKFLOW -----------------------------------------------------------
# Create provision.sh script for Podman VM
$provisionScriptPath = Join-Path $PSScriptRoot 'provision.sh'
if ($SetupPodmanVM -and -not (Test-Path $provisionScriptPath)) {
    Write-Log -Level INFO -Message "Creating provision.sh script"
    $provisionScript = @'
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

# Enable podman socket for remote connections (optional)
echo "Enabling podman socket..."
systemctl --user enable --now podman.socket
systemctl --user status podman.socket

# Set lingering for current user to keep services running
loginctl enable-linger $(whoami)

echo "VM provisioning completed successfully!"
'@
    Set-Content -Path $provisionScriptPath -Value $provisionScript -Encoding UTF8
    Write-Log -Level SUCCESS -Message "Created provision.sh script at $provisionScriptPath"
}

# Execute main workflow based on setup flags
try {
    # Setup Podman VM if requested
    if ($SetupPodmanVM) {
        Write-Log -Level INFO -Message "Starting Podman VM setup"
        Write-Log -Level INFO -Message "VM rootful mode: $($IsRootful ? 'Enabled (default)' : 'Disabled')"
        Invoke-WithRetry -ScriptBlock { Test-PodmanPrerequisite } -ActionName 'Validate prerequisites'
        Remove-ExistingMachine -Name $MachineName
        # Initialize the machine with cgroups-v2 support via systemd cgroup manager
        Initialize-NewMachine -Name $MachineName -Cpus $VMCpus -MemoryMB $VMMemoryMB -DiskGB $VMDiskSizeGB -Rootful $IsRootful

        $sshInfo = Get-SSHInfo -Name $MachineName

        # Deploy in-VM assets
        Write-Log -Level INFO -Message "Deploying assets to VM"
        Copy-ToVM -Src $provisionScriptPath -Dest "/home/$($sshInfo.User)/provision.sh" -SSH $sshInfo
        Copy-ToVM -Src $CertificatePath -Dest "/home/$($sshInfo.User)/ZscalerRootCertificate-2048-SHA256.crt" -SSH $sshInfo
        Copy-ToVM -Src $GitCABundlePath -Dest "/home/$($sshInfo.User)/.git-ca-bundle.pem" -SSH $sshInfo

        # Copy bashrc if it exists
        if (Test-Path $BashrcPath) {
            Copy-ToVM -Src $BashrcPath -Dest "/home/$($sshInfo.User)/.bashrc" -SSH $sshInfo
        }

        # Make provision script executable and run it
        Write-Log -Level INFO -Message "Running provisioning script in VM"
        Invoke-InVM -Cmd "chmod +x ~/provision.sh && ~/provision.sh" -SSH $sshInfo

        # Test Windows container support
        Install-WindowsContainerSupport

        # Deploy bootcdev image if requested
        if ($DeployBootcImage) {
            Write-Log -Level INFO -Message "Starting bootcdev image deployment"

            # Define container files path
            $containerFilesPath = Join-Path $PSScriptRoot "containers"

            # Check if container files directory exists
            if (-not (Test-Path $containerFilesPath)) {
                Write-Log -Level WARNING -Message "Container files directory not found at: $containerFilesPath"
                Write-Log -Level INFO -Message "Creating default container files directory"
                New-Item -Path $containerFilesPath -ItemType Directory -Force | Out-Null

                # Here you might want to create default container files if they don't exist
                # This is just a placeholder - you'd need to implement this based on your needs
                Write-Log -Level WARNING -Message "Default container files would need to be created"
            }

            # Deploy the bootc image
            try {
                $deployResult = Deploy-BootcImage -SSH $sshInfo -ContainerFilesPath $containerFilesPath

                if ($deployResult) {
                    # Test the deployed image
                    $testResults = Test-BootcImage -SSH $sshInfo -Detailed

                    if ($testResults.ImageExists -and $testResults.CanStart) {
                        Write-Log -Level SUCCESS -Message "bootcdev image deployed and tested successfully"
                    } else {
                        Write-Log -Level WARNING -Message "bootcdev image deployment completed but tests indicate issues"
                    }
                }
            }
            catch {
                Write-Log -Level ERROR -Message "Failed to deploy bootcdev image: $_"
            }
        }

        Write-Log -Level SUCCESS -Message "Podman VM setup completed successfully"
    }

    # Setup Windows container tools if requested
    if ($SetupWindowsTools) {
        Write-Log -Level INFO -Message "Starting Windows container tools setup"
        Install-ContainerTools -SSHPublicKey $SSHPublicKey
        Write-Log -Level SUCCESS -Message "Windows container tools setup completed successfully"
    }
}
catch {
    Write-Log -Level ERROR -Message "Container setup failed with error: $_"
    throw "Container setup failed: $_"
}
finally {
    Write-Log -Level INFO -Message "Container environment setup process completed at $(Get-Date)"
    Write-Log -Level INFO -Message "Log file: $global:LogFile"
}

# Add an explicit main entry marker, so script can be dot-sourced without side effects
if ($MyInvocation.InvocationName -eq '.') {
    return
}

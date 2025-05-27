<#
.SYNOPSIS
Comprehensive container environment setup for Windows 11 - combines Podman VM setup and Windows container tools installation.

.DESCRIPTION
This script provides a complete container development environment by:
* Setting up a Podman VM with Linux & Windows container support
* Installing and configuring containerd, CNI plugins, nerdctl, cri-tools, BuildKit, and OpenSSH

Features:
* Self-elevates to Administrator
* Validates prerequisites (certs, Podman, Windows features)
* Tears down & rebuilds VM using best-practice verbs
* Deploys assets: provision.sh, certs, .bashrc
* Executes in-VM provisioning, then tests Windows NanoServer container
* Installs containerd, CNI plugins, nerdctl, cri-tools, BuildKit directly on Windows
* Configures OpenSSH for remote management

.PARAMETER MachineName
Name of the Podman machine to create (default: podman-machine-default)

.PARAMETER CertificatePath
Path to Zscaler Root Certificate

.PARAMETER GitCABundlePath
Path to Git CA bundle

.PARAMETER BashrcPath
Path to custom .bashrc file for the Podman VM

.PARAMETER VMCpus
Number of CPUs to allocate to the Podman VM

.PARAMETER VMMemoryMB
Amount of memory (MB) to allocate to the Podman VM

.PARAMETER VMDiskSizeGB
Disk size (GB) for the Podman VM

.PARAMETER IsRootful
Whether to create a rootful Podman machine (default: $true, recommended for running Windows containers)

.PARAMETER SSHPublicKey
Public key material to seed into Administrators' authorized_keys for Windows container tools.
If not provided, the script will automatically use the Podman Desktop SSH public key.

.PARAMETER SetupPodmanVM
Whether to set up the Podman VM (default: $true)

.PARAMETER SetupWindowsTools
Whether to set up Windows container tools (default: $true)

.PARAMETER DeployBootcImage
Whether to build and deploy the bootc container image (default: $true)

.PARAMETER MaxRetries
Maximum number of retries for operations

.PARAMETER RetryDelaySeconds
Delay between retries in seconds
#>

[CmdletBinding()]
Param(
    # Podman VM parameters
    [string]$MachineName = 'podman-machine-default',
    [string]$CertificatePath = "$env:USERPROFILE\certs\ZscalerRootCertificate-2048-SHA256.crt",
    [string]$GitCABundlePath = "$env:USERPROFILE\certs\.git-ca-bundle.pem",
    [string]$BashrcPath = "C:\Tools\podman-setup\.bashrc",
    [int]$VMCpus = 10,
    [int]$VMMemoryMB = 10096,
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
        [int]$MaxRetries = $script:MaxRetries,
        [int]$DelaySeconds = $script:RetryDelaySeconds,
        [object[]]$ArgumentList
    )
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

function Add-ToPath {
    [CmdletBinding()] Param([Parameter(Mandatory)][string]$Entry)
    $mp = [Environment]::GetEnvironmentVariable('Path','Machine')
    if ($mp.Split(';') -notcontains $Entry) {
        [Environment]::SetEnvironmentVariable('Path', "$mp;$Entry", 'Machine')
        Write-Log -Level INFO -Message "Injected $Entry into Machine PATH."
    }
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
        [Environment]::GetEnvironmentVariable('Path','User')
}

function Copy-ToVM {
    [CmdletBinding()] Param(
        [Parameter(Mandatory)][string]$Src,
        [Parameter(Mandatory)][string]$Dest,
        [Parameter(Mandatory)][hashtable]$SSH
    )
    # For Podman VM, we explicitly use the VM's internal user (not domain user)

    # Remove domain prefix if present in user
    $user = $SSH.User -replace '^.*\\', ''

    # Use Windows built-in OpenSSH
    $scpPath = "$env:SystemRoot\System32\OpenSSH\scp.exe"

    # Ensure we can find SCP
    if (-not (Test-Path $scpPath)) {
        Write-Log -Level WARNING -Message "Could not find Windows OpenSSH SCP at $scpPath, falling back to PATH"
        $scpPath = "scp"  # Fall back to PATH-based resolution
    } else {
        Write-Log -Level INFO -Message "Using Windows built-in SCP: $scpPath"
    }

    # The port argument for scp is capital -P
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
        $Src
    )

    # Use 127.0.0.1 instead of localhost for more reliable connections
    $scpArgs += "$user@127.0.0.1:$Dest"

    try {
        Write-Log -Level INFO -Message "Copy '$Src' (Attempt 1/$MaxRetries)"
        & $scpPath @scpArgs
        if ($LASTEXITCODE -ne 0) {
            throw "SCP command failed with exit code $LASTEXITCODE"
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to copy file to VM: $($_.Exception.Message)"
        throw
    }
}

function Invoke-InVM {
    [CmdletBinding()] Param(
        [Parameter(Mandatory)][string]$Cmd,
        [Parameter(Mandatory)][hashtable]$SSH
    )
    # For Podman VM, we explicitly use the VM's internal user (not domain user)

    # Remove domain prefix if present in user
    $user = $SSH.User -replace '^.*\\', ''

    # Use Windows built-in OpenSSH
    $sshPath = "$env:SystemRoot\System32\OpenSSH\ssh.exe"

    # Ensure we can find SSH
    if (-not (Test-Path $sshPath)) {
        Write-Log -Level WARNING -Message "Could not find Windows OpenSSH client at $sshPath, falling back to PATH"
        $sshPath = "ssh"  # Fall back to PATH-based resolution
    } else {
        Write-Log -Level INFO -Message "Using Windows built-in SSH: $sshPath"
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
        # Modify the command to avoid terminal control characters
        "TERM=dumb $Cmd"
    )

    try {
        Write-Log -Level INFO -Message "In-VM: $Cmd (Attempt 1/$MaxRetries)"
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
}
function Invoke-DownloadAndExtract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][ValidateSet('tar','zip')][string]$Format
    )
    $file = Join-Path $DevRoot ([IO.Path]::GetFileName($Url))
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
    param()

    $podmanPubKeyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine.pub"

    if (-not (Test-Path $podmanPubKeyPath)) {
        Write-Log -Level ERROR -Message "Podman Desktop SSH public key not found at: $podmanPubKeyPath"
        throw "SSH public key not found. Please ensure Podman Desktop is properly installed."
    }

    $publicKeyContent = Get-Content $podmanPubKeyPath -Raw
    $publicKeyContent = $publicKeyContent.Trim()

    Write-Log -Level INFO -Message "Successfully read Podman Desktop public key"
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

    # Add the --cgroup-manager=systemd parameter to enable cgroups-v2
    $cmd = "podman machine init $Name --cpus $Cpus --memory $MemoryMB --disk-size $DiskGB $rootfulFlag --cgroup-manager=systemd"
    Invoke-Expression $cmd

    Write-Log -Level INFO -Message "Starting Podman machine: $Name"
    & podman machine start $Name

    # Verify cgroups-v2 is properly configured
    Write-Log -Level INFO -Message "Verifying cgroups configuration..."
    try {
        $cgroupCheck = & podman machine ssh $Name "grep -s cgroup2 /proc/filesystems || echo 'cgroups-v2 not enabled'"
        if ($cgroupCheck -match "cgroups-v2 not enabled") {
            Write-Log -Level WARNING -Message "cgroups-v2 might not be properly enabled. Will attempt to reconfigure."
            # Stop the machine to reconfigure
            & podman machine stop $Name
            # Set cgroup manager to systemd which enables cgroups-v2
            & podman machine set --rootful --cgroup-manager systemd $Name
            # Restart the machine
            & podman machine start $Name
            # Verify again
            $cgroupCheck = & podman machine ssh $Name "grep -s cgroup2 /proc/filesystems || echo 'cgroups-v2 still not enabled'"
            if ($cgroupCheck -match "cgroups-v2 still not enabled") {
                Write-Log -Level WARNING -Message "cgroups-v2 configuration failed. Some features may not work correctly."
            } else {
                Write-Log -Level SUCCESS -Message "cgroups-v2 successfully configured after reconfiguration."
            }
        } else {
            Write-Log -Level SUCCESS -Message "cgroups-v2 properly configured."
        }
    } catch {
        Write-Log -Level WARNING -Message "Could not verify cgroups configuration: $_"
    }

    Write-Log -Level SUCCESS -Message "Podman machine initialized and started: $Name"
}

function Get-SSHInfo {
    [CmdletBinding()]
    param([string]$Name)

    Write-Log -Level INFO -Message "Retrieving SSH connection info for: $Name"

    # Get the machine information
    $machineInfo = & podman machine inspect $Name | ConvertFrom-Json

    # Check if the machine has a valid SSH Identity Path
    $machineSpecificKeyExists = $false
    if ($machineInfo.SSHConfig.IdentityPath -and (Test-Path $machineInfo.SSHConfig.IdentityPath)) {
        $machineSpecificKeyExists = $true
        Write-Log -Level INFO -Message "Using machine-specific SSH key: $($machineInfo.SSHConfig.IdentityPath)"
    }

    # Fallback to Podman Desktop keys if machine-specific key doesn't exist
    $podmanKeyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine"
    $podmanPubKeyPath = Join-Path $env:USERPROFILE ".local\share\containers\podman\machine\machine.pub"

    # Determine which key to use
    $keyPath = $machineSpecificKeyExists ? $machineInfo.SSHConfig.IdentityPath : $podmanKeyPath
    $pubKeyPath = $machineSpecificKeyExists ? "$($machineInfo.SSHConfig.IdentityPath).pub" : $podmanPubKeyPath

    # Verify the selected SSH key exists
    if (-not (Test-Path $keyPath)) {
        Write-Log -Level ERROR -Message "SSH private key not found at: $keyPath"
        throw "SSH private key not found. Please ensure Podman is properly installed."
    }

    # Determine user: prefer SSHConfig.User, fallback to 'root' or 'user' based on Rootful
    $user = $null
    if ($machineInfo.SSHConfig.User) {
        $user = $machineInfo.SSHConfig.User
    } elseif ($machineInfo.Rootful -eq $true) {
        $user = 'root'
    } else {
        $user = 'user'
    }

    $sshInfo = @{
        User = $user
        Port = $machineInfo.SSHConfig.Port
        KeyPath = $keyPath
        PubKeyPath = $pubKeyPath
        SocketPath = $machineInfo.ConnectionInfo.PodmanSocket
        UsingMachineKey = $machineSpecificKeyExists
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
            $SSHPublicKey = Get-PodmanDesktopPublicKey
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to read Podman Desktop public key: $($_.Exception.Message)"
            throw "SSH public key is required for Windows container tools setup. Either provide -SSHPublicKey parameter or ensure Podman Desktop is installed."
        }
    }

    # Define global variables for Windows container tools
    $script:DevRoot = 'C:\devtools'
    $script:ContainerdVersion = '2.1.0'
    $script:Arch = 'amd64'
    $script:CniPluginVersion = '1.7.1'
    $script:NerdctlVersion = '2.1.1'
    $script:CriToolsVersion = '1.33.0'

    Write-Log -Level INFO -Message "Starting Windows container tools installation"

    # Environment preparation
    Write-Log -Level INFO -Message 'Enabling Containers and Hyper-V features'
    Enable-WindowsOptionalFeature -Online -FeatureName Containers,Microsoft-Hyper-V -All | Out-Null

    New-Item -Path $DevRoot -ItemType Directory -Force | Out-Null

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

    $cdPath = Join-Path $DevRoot 'containerd'
    New-Item -Path $cdPath -ItemType Directory -Force | Out-Null

    $cdUrl = "https://github.com/containerd/containerd/releases/download/v$ContainerdVersion/containerd-$ContainerdVersion-windows-$Arch.tar.gz"
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
    $cdPath = Join-Path $DevRoot 'containerd'
    $cniBin = Join-Path $cdPath 'cni\bin'
    $cniConf = Join-Path $cdPath 'cni\conf'
    New-Item -Path $cniBin,$cniConf -ItemType Directory -Force | Out-Null

    $cniUrl = "https://github.com/containernetworking/plugins/releases/download/v$CniPluginVersion/cni-plugins-windows-$Arch-v$CniPluginVersion.tgz"
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
        @{ Name = 'nerdctl'; Ver = $NerdctlVersion; Url = "https://github.com/containerd/nerdctl/releases/download/v$NerdctlVersion/nerdctl-$NerdctlVersion-windows-$Arch.tar.gz" },
        @{ Name = 'crictl'; Ver = $CriToolsVersion; Url = "https://github.com/kubernetes-sigs/cri-tools/releases/download/v$CriToolsVersion/crictl-v$CriToolsVersion-windows-$Arch.tar.gz" },
        @{ Name = 'critest'; Ver = $CriToolsVersion; Url = "https://github.com/kubernetes-sigs/cri-tools/releases/download/v$CriToolsVersion/critest-v$CriToolsVersion-windows-$Arch.tar.gz" }
    )) {
        Write-Log -Level INFO -Message "Installing $($tool.Name) v$($tool.Ver)"
        $dest = Join-Path $DevRoot $tool.Name
        New-Item -Path $dest -ItemType Directory -Force | Out-Null
        Invoke-DownloadAndExtract -Url $tool.Url -Destination $dest -Format tar
        Add-ToPath -Entry $dest
    }
}

function Install-BuildKit {
    Write-Log -Level INFO -Message 'Installing BuildKit'
    $bkApi = 'https://api.github.com/repos/moby/buildkit/releases/latest'
    $bkTag = (Invoke-RestMethod -Uri $bkApi -UseBasicParsing).tag_name.TrimStart('v')
    $bkUrl = "https://github.com/moby/buildkit/releases/download/v$bkTag/buildkit-v$bkTag.windows-$Arch.tar.gz"
    $bkRoot = Join-Path $DevRoot 'buildkit'
    New-Item -Path $bkRoot -ItemType Directory -Force | Out-Null

    Invoke-DownloadAndExtract -Url $bkUrl -Destination $bkRoot -Format tar
    Add-ToPath -Entry $bkRoot

    $cdPath = Join-Path $DevRoot 'containerd'
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
        Copy-ToVM -Src $BashrcPath -Dest "/home/$($sshInfo.User)/.bashrc" -SSH $sshInfo

        # Deploy container configuration files
        Write-Log -Level INFO -Message "Deploying container configuration files to VM"
        $containersConfigDir = Join-Path $PSScriptRoot 'containers'

        # Copy auth.json to the proper location for container authentication
        $authJsonPath = Join-Path $containersConfigDir 'auth.json'
        if (Test-Path $authJsonPath) {
            Copy-ToVM -Src $authJsonPath -Dest "/home/$($sshInfo.User)/.config/containers/auth.json" -SSH $sshInfo
        }

        # Copy containers.conf for container runtime configuration
        $containersConfPath = Join-Path $containersConfigDir 'containers.conf'
        if (Test-Path $containersConfPath) {
            Copy-ToVM -Src $containersConfPath -Dest "/home/$($sshInfo.User)/.config/containers/containers.conf" -SSH $sshInfo
        }

        # Copy registries.conf for registry configuration
        $registriesConfPath = Join-Path $containersConfigDir 'registries.conf'
        if (Test-Path $registriesConfPath) {
            Copy-ToVM -Src $registriesConfPath -Dest "/home/$($sshInfo.User)/.config/containers/registries.conf" -SSH $sshInfo
        }

        # Copy policy.json for signature verification policy
        $policyJsonPath = Join-Path $containersConfigDir 'policy.json'
        if (Test-Path $policyJsonPath) {
            Copy-ToVM -Src $policyJsonPath -Dest "/home/$($sshInfo.User)/.config/containers/policy.json" -SSH $sshInfo
        }

        # Copy storage.conf for storage configuration
        $storageConfPath = Join-Path $containersConfigDir 'storage.conf'
        if (Test-Path $storageConfPath) {
            Copy-ToVM -Src $storageConfPath -Dest "/home/$($sshInfo.User)/.config/containers/storage.conf" -SSH $sshInfo
        }

        # Create directories and set proper permissions in VM
        Invoke-InVM -Cmd "mkdir -p ~/.config/containers && chmod 700 ~/.config/containers" -SSH $sshInfo

        # Execute the provision script inside VM
        Write-Log -Level INFO -Message "Executing provision script in VM"
        Invoke-InVM -Cmd "chmod +x ~/provision.sh && ~/provision.sh" -SSH $sshInfo

        # Validate Windows container support
        Install-WindowsContainerSupport

        # Deploy bootc image if requested
        if ($DeployBootcImage) {
            try {
                Write-Log -Level INFO -Message "Starting bootc image deployment"
                $containerFilesPath = Join-Path $PSScriptRoot 'containers'

                # Deploy the bootc image
                Deploy-BootcImage -SSH $sshInfo -ContainerFilesPath $containerFilesPath

                # Test the deployment
                Write-Log -Level INFO -Message "Testing bootc image deployment"
                $testResults = Test-BootcImage -SSH $sshInfo -Detailed

                if ($testResults.ImageExists -and $testResults.CanStart) {
                    Write-Log -Level SUCCESS -Message "bootc image deployment and testing completed successfully"
                    Write-Log -Level INFO -Message "To run the container, use: podman machine ssh $MachineName '~/container-files/run-container.sh'"
                } else {
                    Write-Log -Level WARNING -Message "bootc image deployment completed but testing found issues"
                    Write-Log -Level INFO -Message "Review logs and manually verify the image"
                }
            }
            catch {
                Write-Log -Level ERROR -Message "Failed to deploy bootc image: $_"
                Write-Log -Level WARNING -Message "Continuing with setup despite bootc image deployment failure"
            }
        } else {
            Write-Log -Level INFO -Message "Skipping bootc image deployment (DeployBootcImage=$DeployBootcImage)"
        }

        Write-Log -Level SUCCESS -Message "Podman VM '$MachineName' is fully operational"
    }

    # Setup Windows container tools if requested
    if ($SetupWindowsTools) {
        Write-Log -Level INFO -Message "Starting Windows container tools setup"
        Install-ContainerTools -SSHPublicKey $SSHPublicKey
    }

    Write-Log -Level SUCCESS -Message "Container environment setup completed successfully!"
    Write-Log -Level INFO -Message "Log file: $global:LogFile"
}
catch {
    Write-Log -Level ERROR -Message "Setup failed: $_"
    Write-Host "For detailed logs, see: $global:LogFile" -ForegroundColor Red
    exit 1
}

param (
    [string]$PropertiesFilePath
)

if (-not (Test-Path $PropertiesFilePath)) {
    Write-Error "The specified properties file does not exist: $PropertiesFilePath"
    exit 1
}

# Function to check if Docker process is running
function Test-DockerRunning {
    $dockerProcess = Get-Process "Docker Desktop" -ErrorAction SilentlyContinue
    return $dockerProcess -ne $null
}

# Function to check if Docker daemon is responsive
function Test-DockerDaemon {
    try {
        docker info | Out-Null
        return $true
    } catch {
        return $false
    }
}

# Function to wait for Docker to start
function Wait-ForDocker {
    param (
        [int]$maxAttempts = 30,
        [int]$waitSeconds = 5
    )
    for ($i = 1; $i -le $maxAttempts; $i++) {
        Write-Output "Checking Docker daemon status... Attempt $i"
        if (Test-DockerDaemon) {
            Write-Output "Docker daemon is running."
            return $true
        }
        if ($i -eq $maxAttempts) {
            Write-Output "Docker daemon did not start within the allotted time."
            return $false
        }
        Write-Output "Docker daemon is not running yet. Waiting for $waitSeconds seconds..."
        Start-Sleep -Seconds $waitSeconds
    }
    return $false
}

# Function to parse .properties file
function Parse-PropertiesFile {
    param (
        [string]$filePath
    )
    $properties = @{}
    Get-Content $filePath | ForEach-Object {
        $line = $_.Trim()
        if (-not $line.StartsWith("#") -and $line.Contains("=")) {
            $key, $value = $line -split "=", 2
            $properties[$key.Trim()] = $value.Trim()
        }
    }
    return $properties
}

# Step 1: Docker Service Start
if (-not (Test-DockerRunning)) {
    Write-Output "Docker Desktop is not running. Starting Docker Desktop..."
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    Start-Sleep -Seconds 10  # Wait a bit for the process to initiate
    if (-not (Wait-ForDocker -maxAttempts 30 -waitSeconds 5)) {
        exit 1
    }
} else {
    Write-Output "Docker Desktop is already running."
    if (-not (Wait-ForDocker -maxAttempts 30 -waitSeconds 5)) {
        exit 1
    }
}

# Docker Login
$sourceRegistryUser = "sandeeep"
$sourceRegistryPasswd = "Psan@3005"
Write-Output "Logging into Docker registry..."
docker login --username $sourceRegistryUser --password $sourceRegistryPasswd

# Trivy Installation
Write-Output "Step 2: Trivy Installation"

# Check if Trivy is already installed
$trivyPath = Get-Command trivy -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Definition
if ($trivyPath) {
    Write-Output "Trivy is already installed at $trivyPath."
} else {
    Write-Output "Trivy is not installed. Proceeding with installation..."

    # Define the download URL and the destination path
    $trivyUrl = "https://github.com/aquasecurity/trivy/releases/download/v0.41.0/trivy_0.41.0_Windows-64bit.zip"
    $trivyZip = "$env:USERPROFILE\Downloads\trivy_0.41.0_Windows-64bit.zip"
    $trivyExtractPath = "$env:USERPROFILE\Trivy"

    # Download the Trivy zip package
    Invoke-WebRequest -Uri $trivyUrl -OutFile $trivyZip

    # Create the extraction directory if it doesn't exist
    if (-not (Test-Path $trivyExtractPath)) {
        New-Item -ItemType Directory -Path $trivyExtractPath
    }

    # Extract the Trivy zip package
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($trivyZip, $trivyExtractPath)

    # Add the Trivy path to the system PATH environment variable for the current session
    $env:Path += ";$trivyExtractPath"

    # Verify Trivy installation
    $trivyExe = Join-Path $trivyExtractPath "trivy.exe"
    if (Test-Path $trivyExe) {
        Write-Output "Trivy is installed at $trivyExe"
    } else {
        Write-Output "Trivy installation failed."
        exit 1
    }
}

# Parse the .properties file
$properties = Parse-PropertiesFile -filePath $PropertiesFilePath

$windowsImages = $properties["windows.images"] -split ","
$linuxImages = $properties["linux.images"] -split ","

# Create directory for Trivy reports if it doesn't exist
$trivyReportPath = "$env:USERPROFILE\TrivyReports"
if (-not (Test-Path $trivyReportPath)) {
    New-Item -ItemType Directory -Path $trivyReportPath
}

# Pull images and scan with Trivy
foreach ($image in $windowsImages + $linuxImages) {
    Write-Output "Pulling Docker image: $image"
    docker pull $image

    # Check if the image is available in the Docker registry
    $imageInfo = docker images --format "{{.Repository}}:{{.Tag}}" $image
    if (-not $imageInfo) {
        Write-Host "Image $image is not available in the Docker registry" -ForegroundColor Red
        continue
    }

    # Create report file path
    $reportFile = "$trivyReportPath\$($image.Replace("/", "_").Replace(":", "_")).html"
    
    # Run Trivy to generate HTML report
    Write-Output "Scanning image with Trivy: $image"
    #trivy image --format template --template "@C:\Users\sande\Trivy\contrib\html.tpl" -o $reportFile $image
    trivy image --format template --template "@https://github.com/aquasecurity/trivy/blob/648ead9553eb2cbeac90e3ef7330a70c352255ac/contrib/html.tpl" -o $reportFile $image

    Write-Output "Trivy report generated: $reportFile"
}

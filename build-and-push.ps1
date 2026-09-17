<#
.SYNOPSIS
    Builds Docker image for PyThales HSM Simulator and pushes to private registry.
.DESCRIPTION
    Builds the Docker image for PyThales (default linux/amd64), tags it with specified tag(s)
    and pushes to registry.hevitech.io.vn.
.PARAMETER Registry
    Docker registry host (default: registry.hevitech.io.vn)
.PARAMETER ImageName
    Image name / repository (default: pythales)
.PARAMETER Tag
    Primary tag for the image (default: latest)
.PARAMETER AdditionalTags
    Array of additional tags (e.g. "0.74", "v0.74", git commit hash)
.PARAMETER Platform
    Target architecture (default: linux/amd64)
.PARAMETER NoPush
    Switch to only build and tag without pushing to registry
.PARAMETER SkipTests
    Skip running tests before building
.EXAMPLE
    .\build-and-push.ps1
    .\build-and-push.ps1 -Tag "0.74" -AdditionalTags "latest"
    .\build-and-push.ps1 -ImageName "3ds/pythales" -Tag "1.0.0"
    .\build-and-push.ps1 -NoPush
#>
[CmdletBinding()]
param (
    [string]$Registry = "registry.hevitech.io.vn",
    [string]$ImageName = "pythales",
    [string]$Tag = "latest",
    [string[]]$AdditionalTags = @(),
    [string]$Platform = "linux/amd64",
    [switch]$NoPush,
    [switch]$SkipTests
)

$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-WarningMsg {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# 1. Locate repository root (directory containing Dockerfile)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = $null

$candidateDirs = @(
    $scriptDir,
    (Join-Path $scriptDir ".."),
    (Get-Location).Path,
    (Join-Path (Get-Location).Path "..")
)

foreach ($dir in $candidateDirs) {
    if (Test-Path (Join-Path $dir "Dockerfile")) {
        $repoRoot = (Resolve-Path $dir).Path
        break
    }
}

if (-not $repoRoot) {
    Write-ErrorMsg "Could not locate 'Dockerfile'. Please run this script from the repository root."
    exit 1
}

$dockerfilePath = Join-Path $repoRoot "Dockerfile"
Write-Step "Repository Root: $repoRoot"
Write-Host "Dockerfile Path: $dockerfilePath"

# 2. Check Docker CLI and Daemon
Write-Step "Checking Docker CLI and Daemon..."
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-ErrorMsg "Docker CLI ('docker') is not installed or not found in PATH."
    exit 1
}

$null = (& docker info 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Docker daemon is not running or not responding."
    Write-Host "Please start Docker Desktop and wait until the engine is fully started, then run this script again." -ForegroundColor Yellow
    exit 1
}
Write-Success "Docker daemon is active and running."

# 3. Optional: Run tests before build
if (-not $SkipTests) {
    Write-Step "Running automated verification tests before build..."
    $pytestCmd = $null
    $venvPytest = Join-Path $repoRoot ".venv\Scripts\pytest.exe"
    $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"

    if (Test-Path $venvPytest) {
        $pytestCmd = $venvPytest
    } elseif (Test-Path $venvPython) {
        $pytestCmd = "$venvPython -m pytest"
    } elseif (Get-Command pytest -ErrorAction SilentlyContinue) {
        $pytestCmd = "pytest"
    }

    if ($pytestCmd) {
        Write-Host "Executing tests via: $pytestCmd"
        Push-Location $repoRoot
        try {
            if ($pytestCmd -eq $venvPytest) {
                & $venvPytest tests test_hmac_suite.py
            } elseif ($pytestCmd.Contains("-m pytest")) {
                & $venvPython -m pytest tests test_hmac_suite.py
            } else {
                pytest tests test_hmac_suite.py
            }
            if ($LASTEXITCODE -ne 0) {
                Write-ErrorMsg "Tests failed! Aborting Docker build to prevent pushing faulty image."
                Write-Host "Use -SkipTests to bypass test execution if necessary." -ForegroundColor Yellow
                exit 1
            }
            Write-Success "All tests passed cleanly."
        } finally {
            Pop-Location
        }
    } else {
        Write-WarningMsg "Pytest not found in virtualenv or PATH. Skipping automated test phase."
    }
} else {
    Write-WarningMsg "Skipping tests (-SkipTests specified)."
}

# 4. Resolve Tags
$allTags = [System.Collections.Generic.List[string]]::new()
if ($Tag) {
    $allTags.Add($Tag)
}

# Automatically add Git short commit hash if available
try {
    $gitShortHash = git -C $repoRoot rev-parse --short HEAD 2>$null
    if ($gitShortHash -and -not $allTags.Contains("sha-$gitShortHash")) {
        $allTags.Add("sha-$gitShortHash")
    }
} catch {
    # Git not available or not in repo
}

if ($AdditionalTags) {
    foreach ($t in $AdditionalTags) {
        if (-not [string]::IsNullOrWhiteSpace($t) -and -not $allTags.Contains($t)) {
            $allTags.Add($t)
        }
    }
}

# Ensure at least 1 tag
if ($allTags.Count -eq 0) {
    $allTags.Add("latest")
}

$primaryTag = $allTags[0]
$fullImageBase = if ($Registry) { "$Registry/$ImageName" } else { $ImageName }
$primaryImageUri = "$fullImageBase`:$primaryTag"

Write-Step "Preparing build for target image:"
Write-Host "  Registry:     $Registry"
Write-Host "  Image Name:   $ImageName"
Write-Host "  Platform:     $Platform"
Write-Host "  Primary Tag:  $primaryImageUri"
Write-Host "  All Tags:     $(($allTags | ForEach-Object { "$fullImageBase`:$_" }) -join ', ')"

# 5. Build Docker Image
Write-Step "Building Docker image: $primaryImageUri ..."
$buildArgs = @("build", "--platform", $Platform, "-t", $primaryImageUri, "-f", $dockerfilePath, $repoRoot)
Write-Host "Command: docker $($buildArgs -join ' ')"

& docker @buildArgs
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Docker build failed."
    exit 1
}
Write-Success "Docker image built successfully: $primaryImageUri"

# 6. Tag additional tags
for ($i = 1; $i -lt $allTags.Count; $i++) {
    $extraTag = $allTags[$i]
    $extraUri = "$fullImageBase`:$extraTag"
    Write-Host "Tagging image: $extraUri"
    & docker tag $primaryImageUri $extraUri
    if ($LASTEXITCODE -ne 0) {
        Write-ErrorMsg "Failed to tag image as: $extraUri"
        exit 1
    }
}
Write-Success "All tags applied."

# 7. Push to Registry
if (-not $NoPush) {
    Write-Step "Pushing images to registry '$Registry'..."
    
    foreach ($t in $allTags) {
        $pushUri = "$fullImageBase`:$t"
        Write-Host "Pushing: $pushUri ..."
        & docker push $pushUri
        if ($LASTEXITCODE -ne 0) {
            Write-ErrorMsg "Failed to push image: $pushUri"
            Write-Host "Hint: Ensure you are logged in to the registry:" -ForegroundColor Yellow
            Write-Host "      docker login $Registry" -ForegroundColor Yellow
            exit 1
        }
        Write-Success "Pushed: $pushUri"
    }
    Write-Success "All images pushed successfully to $Registry!"
} else {
    Write-WarningMsg "Skipping push (-NoPush specified). Image remains stored locally."
}

# 8. Summary
Write-Host "`n===========================================================" -ForegroundColor Green
Write-Host "  PYTHALES DOCKER BUILD & PUBLISH COMPLETE" -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Green
Write-Host "Primary Image:  $primaryImageUri" -ForegroundColor White
if (-not $NoPush) {
    Write-Host "`nTo pull and run this image on another server:" -ForegroundColor Cyan
    Write-Host "  docker pull $primaryImageUri" -ForegroundColor Yellow
    Write-Host "  docker run -d -p 1500:1500 --name pythales-hsm $primaryImageUri" -ForegroundColor Yellow
}
Write-Host "===========================================================`n" -ForegroundColor Green

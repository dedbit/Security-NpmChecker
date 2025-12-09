<#PSScriptInfo
.VERSION 1.0

.GUID 8f4c2a1d-7e9b-4c5a-8f3b-2e1c5d8f4a9b

.AUTHOR Security Team

.COMPANYNAME Security-NpmChecker
#>

<#
.SYNOPSIS
    Safely installs npm packages with script execution disabled and security scanning.
.DESCRIPTION
    This script installs npm packages using the --ignore-scripts flag to prevent execution of 
    potentially malicious preinstall/postinstall scripts (such as those used by Shai-Hulud 2.0).
    It also optionally scans the target project directory for known compromised packages before 
    and after installation.
.PARAMETER PackageName
    The name(s) of the npm package(s) to install. Can be a single package or comma-separated list.
.PARAMETER ProjectPath
    The root directory path of the npm project. Defaults to current directory.
.PARAMETER SkipScanner
    If specified, skips the security scanner before and after installation.
.PARAMETER UseCi
    If specified, uses 'npm ci' instead of 'npm install'. Recommended for locked dependencies.
.PARAMETER SaveDev
    If specified, saves package to devDependencies instead of dependencies.
.EXAMPLE
    Windows PS> .\Install-NpmSafePackage.ps1 -PackageName "express" -ProjectPath "C:\myproject"
.EXAMPLE
    Windows PS> .\Install-NpmSafePackage.ps1 -PackageName "typescript,eslint" -ProjectPath "." -SaveDev
.EXAMPLE
    Windows PS> .\Install-NpmSafePackage.ps1 -PackageName "lodash" -ProjectPath "." -SkipScanner
.NOTES
    Tested with:
    - PowerShell 5.1.26100.7019 on Windows 11
    - PowerShell 7.4.13 on Windows 11
    - PowerShell 7.5.0 on Ubuntu 24.04.1 LTS
#>

Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$PackageName,

    [Parameter(Mandatory=$false)]
    [string]$ProjectPath = ".",

    [switch]$SkipScanner,

    [switch]$UseCi,

    [switch]$SaveDev,

    [switch]$SkipGlobalNpmPackagesScan
)

# Script configuration
$scriptVersion = "1.0"
$scannerScriptName = "Run-ShaiHuludScanner.ps1"

# Validate ProjectPath
if (-not (Test-Path -Path $ProjectPath)) {
    Write-Error "The specified project path does not exist: $ProjectPath"
    exit 1
}

$ProjectPath = (Resolve-Path $ProjectPath).Path

# Check if package.json exists
$packageJsonPath = Join-Path -Path $ProjectPath -ChildPath "package.json"
if (-not (Test-Path -Path $packageJsonPath)) {
    Write-Error "package.json not found in: $ProjectPath"
    Write-Error "Make sure you're pointing to the root of an npm project."
    exit 1
}

# Find scanner script
$scannerPath = $null
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$searchPaths = @(
    (Join-Path -Path $currentDir -ChildPath "..\ShaiHuludChecker\$scannerScriptName"),
    (Join-Path -Path $currentDir -ChildPath "$scannerScriptName"),
    (Join-Path -Path $ProjectPath -ChildPath "ShaiHuludChecker\$scannerScriptName"),
    (Join-Path -Path $ProjectPath -ChildPath "$scannerScriptName")
)

foreach ($path in $searchPaths) {
    if (Test-Path -Path $path) {
        $scannerPath = (Resolve-Path $path).Path
        break
    }
}

if (-not $scannerPath -and -not $SkipScanner) {
    Write-Warning "Scanner script not found at expected locations. Skipping security scan."
    Write-Warning "Searched in:"
    $searchPaths | ForEach-Object { Write-Warning "  - $_" }
    $SkipScanner = $true
}

# Display header
Write-Host
Write-Host "+========================================+" -ForegroundColor Cyan
Write-Host "|   NPM SAFE PACKAGE INSTALLER v$scriptVersion   |" -ForegroundColor Cyan
Write-Host "+========================================+" -ForegroundColor Cyan
Write-Host
Write-Host "Package(s): $PackageName"
Write-Host "Project Path: $ProjectPath"
Write-Host "Install Method: $(if ($UseCi) { 'npm ci' } else { 'npm install' })"
Write-Host "Save to: $(if ($SaveDev) { 'devDependencies' } else { 'dependencies' })"
Write-Host "Scanner: $(if ($SkipScanner) { 'DISABLED' } else { 'ENABLED' })"
Write-Host

# Security disclaimer
Write-Host "[ SECURITY NOTES ]" -ForegroundColor Yellow
Write-Host "  - Scripts execution is DISABLED (--ignore-scripts flag)"
Write-Host "  - This prevents malicious preinstall/postinstall scripts from running"
Write-Host "  - The scanner checks for known compromised packages"
Write-Host

# Run pre-installation scan if enabled
if (-not $SkipScanner) {
    Write-Host "+------------------------------------+" -ForegroundColor Magenta
    Write-Host "|   PRE-INSTALLATION SECURITY SCAN   |" -ForegroundColor Magenta
    Write-Host "+------------------------------------+" -ForegroundColor Magenta
    Write-Host
    
    $scanArgs = @($ProjectPath)
    if ($SkipGlobalNpmPackagesScan) {
        $scanArgs += "-SkipGlobalNpmPackagesScan"
    }
    
    try {
        & $scannerPath @scanArgs
    } catch {
        Write-Error "Scanner execution failed: $($_.Exception.Message)"
        Write-Host "Continue? (Y/n): " -NoNewline
        $response = Read-Host
        if ($response -eq "n") {
            exit 1
        }
    }
    
    Write-Host
}

# Prepare npm install command
$npmCommand = if ($UseCi) { "ci" } else { "install" }
$npmArgs = @($npmCommand, "--ignore-scripts")

if (-not $UseCi) {
    # Only add package names for 'npm install', not for 'npm ci'
    $npmArgs += $PackageName.Split(",") | ForEach-Object { $_.Trim() }
}

if ($SaveDev) {
    $npmArgs += "--save-dev"
}

Write-Host "+------------------------------------+" -ForegroundColor Green
Write-Host "|   INSTALLING PACKAGES             |" -ForegroundColor Green
Write-Host "+------------------------------------+" -ForegroundColor Green
Write-Host
Write-Host "Running: npm $($npmArgs -join ' ')"
Write-Host

# Change to project directory and run npm install
Push-Location -Path $ProjectPath
try {
    $npmOutput = npm @npmArgs 2>&1
    $npmExitCode = $LASTEXITCODE
    
    Write-Host $npmOutput
    Write-Host
    
    if ($npmExitCode -ne 0) {
        Write-Error "npm command failed with exit code: $npmExitCode"
        Pop-Location
        exit $npmExitCode
    }
    
    Write-Host "✓ Package installation completed successfully" -ForegroundColor Green
    Write-Host
} catch {
    Write-Error "Failed to execute npm install: $($_.Exception.Message)"
    Pop-Location
    exit 1
} finally {
    Pop-Location
}

# Run post-installation scan if enabled
if (-not $SkipScanner) {
    Write-Host "+------------------------------------+" -ForegroundColor Magenta
    Write-Host "|   POST-INSTALLATION SECURITY SCAN  |" -ForegroundColor Magenta
    Write-Host "+------------------------------------+" -ForegroundColor Magenta
    Write-Host
    
    $scanArgs = @($ProjectPath)
    if ($SkipGlobalNpmPackagesScan) {
        $scanArgs += "-SkipGlobalNpmPackagesScan"
    }
    
    try {
        & $scannerPath @scanArgs
    } catch {
        Write-Error "Scanner execution failed: $($_.Exception.Message)"
    }
    
    Write-Host
}

# Final summary
Write-Host "+========================================+" -ForegroundColor Cyan
Write-Host "|   INSTALLATION COMPLETE             |" -ForegroundColor Cyan
Write-Host "+========================================+" -ForegroundColor Cyan
Write-Host
Write-Host "Package(s) installed safely with script execution disabled." -ForegroundColor Green
Write-Host
Write-Host "Next steps:"
Write-Host "  1. Review package.json to verify dependency versions"
Write-Host "  2. Run 'npm audit' to check for known vulnerabilities"
Write-Host "  3. Test your application thoroughly before deploying"
Write-Host

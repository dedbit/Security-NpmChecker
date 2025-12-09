<#PSScriptInfo
.VERSION 1.2

.GUID 38d58180-9315-4919-a3be-59329e0ad445

.AUTHOR mattias.uldin@fellowmind.se

.COMPANYNAME Fellowmind Sweden
#>

<#
.SYNOPSIS
    Scans a specified path for Shai-Hulud 2.0 infections (aka Sha1-Hulud).
.DESCRIPTION
    This script scans the provided directory path for signs of Shai-Hulud 2.0 infections by looking for known malicious files and infection patterns in package.json files.
.PARAMETER ScanRootPath
    The root directory path to scan.
.EXAMPLE
    Windows PS> .\Run-ShaiHuludScanner.ps1 "C:\dev"
.EXAMPLE
    Unix PS> ./Run-ShaiHuludScanner.ps1 "/workspaces/myproject"
.NOTES
    Tested with:
    - PowerShell 5.1.26100.7019 on Windows 11
    - PowerShell 7.4.13 on Windows 11
    - PowerShell 7.5.0 on Ubuntu 24.04.1 LTS
#>
Param(
    [Parameter(Mandatory=$false, Position=0)]
    [string]$ScanRootPath = (Get-Location).Path,

    [switch]$SkipGlobalNpmPackagesScan
)

$scriptVersion = (Select-String -Path $MyInvocation.MyCommand.Path -Pattern '^\s*\.VERSION\s+(.+)').Matches[0].Groups[1].Value

# Validate ScanRootPath
if (-not (Test-Path -Path $ScanRootPath)) {
    Write-Error "The specified path does not exist: $ScanRootPath"
    exit 1
}

# Validate global npm packages path and find nvm root path, if not skipped
$globalNpmNodeModulesPath = $null
$nvmNodeVersionsPath = $null
if (-not $SkipGlobalNpmPackagesScan) {
    $globalNpmNodeModulesPath = $null
    try {
        $globalNpmNodeModulesPath = (npm root -g)
    }catch {
        Write-Error "npm is not installed or not found in PATH. Cannot scan global npm packages."
        Write-Host "You can skip scanning global npm packages by using the -SkipGlobalNpmPackagesScan switch."
        exit 1
    }

    if (-not (Test-Path -Path $globalNpmNodeModulesPath)) {
        Write-Error "The global npm packages path does not exist: $globalNpmNodeModulesPath"
        Write-Host "You can skip scanning global npm packages by using the -SkipGlobalNpmPackagesScan switch."
        exit 1
    }
    else {
        $globalNpmNodeModulesPath = (Resolve-Path $globalNpmNodeModulesPath).Path
    }

    try {
        if ((nvm --version)) {
            Write-Verbose "NVM (Node Version Manager) detected. Attempting to get NVM node versions path..."
            $nvmRootOutput = (nvm root) -join "`n"
            Write-Verbose "NVM root output: $nvmRootOutput"
            if ($nvmRootOutput -match "(?m)^\s*Current Root:\s*(.+?)\s*$") {
                $nvmNodeVersionsPath = $matches[1]
                Write-Verbose "NVM node versions path detected: $nvmNodeVersionsPath"
            }
        }
    } catch {
        Write-Verbose "NVM (Node Version Manager) not found or path could not be parsed from `"nvm root`" output. Skipping NVM node versions scan."
    }
}

$scanStartTime = Get-Date
$ScanRootPath = (Resolve-Path $ScanRootPath).Path
$userHomePath = [Environment]::GetFolderPath("UserProfile")

$packageScanPatterns = @("node setup_bun.js") # Pattern indicating infection in package.json by adding the pattern as a preinstall script
$knownMaliciousFiles = @("bun_environment.js", "setup_bun.js") # Known malicious file names used by the Shai-Hulud 2.0 infection
$filesOfInterestNames = @("package.json") + $knownMaliciousFiles
$trufflehogInUserHomePath = ".truffler-cache"

# Report object to store scan results
$report = [PSCustomObject]@{
    InfectedFiles = @()
    SuspectedFiles = @()
    FilesWithScanError = @()
    NpmPackageWarnings = @()
    ScanInformation = [PSCustomObject]@{
        ScriptVersion = $scriptVersion
        FilesWithScanError = $null
        InfectedFilesFound = $null
        SuspectedFilesFound = $null
        NpmPackageWarningsFound = $null
        FilesScanned = 0
        PackageJsonFilesScanned = 0
        TrufflehogFound = $null
        SkipGlobalNpmPackagesScan = $SkipGlobalNpmPackagesScan.IsPresent
        Paths = [PSCustomObject]@{
            ScanRoot = (Resolve-Path $ScanRootPath).Path
            UserHome = $userHomePath
            GlobalNpmNodeModules = $globalNpmNodeModulesPath
            NvmNodeVersions = $nvmNodeVersionsPath
        }
        Environment = [PSCustomObject]@{
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            OS = $PSVersionTable.OS
        }
        ScanStartTime = $scanStartTime.ToString()
        ScanEndTime = $null
        ScanDuration = $null
    }
}

function Test-File {
    param (
        $File
    )

    $filePath = $File.FullName
    $fileName = $File.Name

    Write-Verbose "Scanning file: $fileName | $filePath"

    if ($fileName -in $knownMaliciousFiles) {
        Write-Warning "Suspected file found: $filePath"
        $script:report.SuspectedFiles += [PSCustomObject]@{ FilePath = $filePath; }
    }

    if ($fileName -eq "package.json") {
        $script:report.ScanInformation.PackageJsonFilesScanned++
        Write-Verbose "Scanning package.json file: $filePath"
        $content = Get-Content -Path $filePath -Raw

        foreach ($scanPattern in $packageScanPatterns) {
            Write-Verbose "Checking for pattern: $scanPattern in $filePath"
            if ($content -like "*$scanPattern*") {
                Write-Warning "Infected file found: $FilePath"
                $script:report.InfectedFiles += [PSCustomObject]@{ FilePath = $filePath; Pattern = $scanPattern }
            }
        }

        # Process known compromised npm packages
        Write-Verbose "Checking for known compromised npm packages in $filePath"
        foreach ($knownCompromisedNpmPackage in $Script:knownCompromisedNpmPackages) {
            $packageName = $knownCompromisedNpmPackage.package_name
            $maliciousVersions = $knownCompromisedNpmPackage.package_versions

            # Check for package name in the file content
            if ($content -like "*`"$packageName`"*") {
                # Try to extract the version from the package.json
                $installedVersion = $null
                try {
                    $packageJson = $content | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($packageJson) {
                        $installedVersion = $packageJson.version
                    }
                } catch {
                    Write-Verbose "Could not parse JSON from $filePath"
                }

                # Check if installed version matches any known malicious versions
                $versionWarning = ""
                if ($installedVersion) {
                    if ($maliciousVersions -split ", " | Where-Object { $_ -eq $installedVersion }) {
                        $versionWarning = " | INSTALLED VERSION $installedVersion MATCHES KNOWN MALICIOUS VERSION"
                        Write-Warning "File with reference to known compromised npm package found (MALICIOUS VERSION DETECTED): $filePath | Package: $packageName | Version: $installedVersion | Known malicious versions: $maliciousVersions"
                    } else {
                        Write-Warning "File with reference to known compromised npm package found: $filePath | Package: $packageName | Version: $installedVersion (Safe - different from malicious: $maliciousVersions)"
                    }
                } else {
                    Write-Warning "File with reference to known compromised npm package found: $filePath | Package: $packageName | Version: (unable to determine)"
                }
                
                $script:report.NpmPackageWarnings += [PSCustomObject]@{
                    FilePath = $filePath;
                    Reason = "Reference to known compromised npm package found";
                    NpmPackageName = $packageName;
                    NpmPackageCurrentVersion = $installedVersion ?? "(unable to determine)";
                    NpmPackageKnownMaliciousVersions = $maliciousVersions;
                    VersionMatch = if ($installedVersion -and ($maliciousVersions -split ", " | Where-Object { $_ -eq $installedVersion })) { "YES - MALICIOUS" } else { "NO - Safe" }
                }
            }

            # Check if the package.json file is located in a folder matching the package name
            if ($File.Directory.FullName.Replace("\", "/") -like "*/$packageName") {
                # Try to extract the version from the package.json
                $installedVersion = $null
                try {
                    $packageJson = $content | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($packageJson) {
                        $installedVersion = $packageJson.version
                    }
                } catch {
                    Write-Verbose "Could not parse JSON from $filePath"
                }

                # Check if installed version matches any known malicious versions
                if ($installedVersion) {
                    if ($maliciousVersions -split ", " | Where-Object { $_ -eq $installedVersion }) {
                        Write-Warning "package.json file located in folder matching known compromised npm package found (MALICIOUS VERSION DETECTED): $filePath | Package: $packageName | Version: $installedVersion | Known malicious versions: $maliciousVersions"
                    } else {
                        Write-Warning "package.json file located in folder matching known compromised npm package found: $filePath | Package: $packageName | Version: $installedVersion (Safe - different from malicious: $maliciousVersions)"
                    }
                } else {
                    Write-Warning "package.json file located in folder matching known compromised npm package found: $filePath | Package: $packageName | Version: (unable to determine)"
                }
                
                $script:report.NpmPackageWarnings += [PSCustomObject]@{
                    FilePath = $filePath;
                    Reason = "package.json located in folder matching known compromised npm package";
                    NpmPackageName = $packageName;
                    NpmPackageCurrentVersion = $installedVersion ?? "(unable to determine)";
                    NpmPackageKnownMaliciousVersions = $maliciousVersions;
                    VersionMatch = if ($installedVersion -and ($maliciousVersions -split ", " | Where-Object { $_ -eq $installedVersion })) { "YES - MALICIOUS" } else { "NO - Safe" }
                }
            }
        }
    }

    $script:report.ScanInformation.FilesScanned++
}

function Test-Folder {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    # Get all target files in the specified path and its subdirectories (including hidden and system files)
    Write-Host "Searching for files recursively in `"$Path`"..." -NoNewline
    $matchingFiles = Get-ChildItem -Path "$Path/*" -Include $script:filesOfInterestNames -Force -Recurse
    Write-Host " completed"
    Write-Host "Found $($matchingFiles.Count) target files."
    Write-Host

    Write-Host "BEGIN: File scan - $Path"
    $fileIndex = 0
    foreach ($file in $matchingFiles) {
        $percentComplete = [math]::Round((($fileIndex++ / $matchingFiles.Count) * 100), 0)
        Write-Progress -Id 0 -Activity "Scanning $Path" `
            -PercentComplete $percentComplete

        try {
            Test-File -File $file
        } catch {
            $script:report.FilesWithScanError += [PSCustomObject]@{ Path = $file.FullName; Error = $_.Exception.Message }
            Write-Host "Error scanning file: $($file.FullName). Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "END: File scan - $Path"
    Write-Host

    Write-Progress -Id 0 -Activity "Task" -Status "Complete" -Completed
}

# Pre-scanning information
$logoBase64 = "Kz09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09Kwp8ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB8CnwgICAgX19fXyAgXyAgICAgICAgICAgXyAgICAgICBfICAgXyAgICAgICBfICAgICAgICAgICBfICAgX19fXyAgICBfX18gICAgIHwKfCAgIC8gX19ffHwgfF9fICAgX18gXyhfKSAgICAgfCB8IHwgfF8gICBffCB8XyAgIF8gIF9ffCB8IHxfX18gXCAgLyBfIFwgICAgfAp8ICAgXF9fXyBcfCAnXyBcIC8gX2AgfCB8X19fX198IHxffCB8IHwgfCB8IHwgfCB8IHwvIF9gIHwgICBfXykgfHwgfCB8IHwgICB8CnwgICAgX19fKSB8IHwgfCB8IChffCB8IHxfX19fX3wgIF8gIHwgfF98IHwgfCB8X3wgfCAoX3wgfCAgLyBfXy8gfCB8X3wgfCAgIHwKfCAgIHxfX19fL3xffCB8X3xcX18sX3xffCAgICAgfF98IHxffFxfXyxffF98XF9fLF98XF9fLF98IHxfX19fXyhfKV9fXy8gICAgfAp8ICAgLyBfX198ICBfX18gX18gXyBfIF9fICBfIF9fICAgX19fIF8gX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB8CnwgICBcX19fIFwgLyBfXy8gX2AgfCAnXyBcfCAnXyBcIC8gXyBcICdfX3wgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHwKfCAgICBfX18pIHwgKF98IChffCB8IHwgfCB8IHwgfCB8ICBfXy8gfCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfAp8ICAgfF9fX18vIFxfX19cX18sX3xffCB8X3xffCB8X3xcX19ffF98ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB8CnwgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHwKKz09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09Kw=="
$decodedLogo = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($logoBase64))
Write-Host $decodedLogo -ForegroundColor Magenta
Write-Host

Write-Host "+-----------------+" -ForegroundColor Magenta
Write-Host "|   INFORMATION   |" -ForegroundColor Magenta
Write-Host "+-----------------+" -ForegroundColor Magenta
Write-Host

Write-Host "Version: $scriptVersion"
Write-Host

Write-Host "[ Notes & disclaimers ]"
Write-Host "  - Scanner aims to aid in detecting Shai-Hulud 2.0 infections or exposure in a given environment."
Write-Host "  - Scanning of multiple paths, locally or in containers, is recommended for better coverage."
Write-Host "  - No guarantees of detection or false positives/negatives are made - this is a best-effort attempt."
Write-Host "  - Always review the scan results manually and take appropriate actions based on organization policies."
Write-Host

Write-Host "[ Scan includes ]"
Write-Host "  - Existence of known malicious files: $($knownMaliciousFiles -join ', ')"
Write-Host "  - Infections in package.json by looking for preinstall script: 'node setup_bun.js'"
Write-Host "  - References to known affected npm packages in packages.json files"
Write-Host "  - Installed npm packages by scanning node_modules folders"
Write-Host "     - Including global npm packages and NVM managed versions if applicable (skippable with script switch)"
Write-Host "  - Traces of Trufflehog tool in user's home directory"
Write-Host

Write-Host "[ References & more information ]"
Write-Host "  - https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm"
Write-Host "  - https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
Write-Host "  - https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack"
Write-Host

Write-Host -NoNewLine "Press any key to start scanning... ";
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
Write-Host
Write-Host

Write-Host "+----------------------+" -ForegroundColor Magenta
Write-Host "|   SCANNING PROCESS   |" -ForegroundColor Magenta
Write-Host "+----------------------+" -ForegroundColor Magenta
Write-Host

# Checking for trufflehog cache folder in user's home directory
$trufflehogCacheFolderPath = Join-Path -Path $userHomePath -ChildPath $trufflehogInUserHomePath
Write-Verbose "Checking for trufflehog cache folder at: $trufflehogCacheFolderPath"
Write-Host "Checking for Trufflehog program which is part of the credentials steeling process... " -NoNewline
if (Test-Path -Path $trufflehogCacheFolderPath -PathType Container) {
    Write-Host "completed"
    Write-Warning "Suspected trufflehog cache folder found: $trufflehogCacheFolderPath"
    $script:report.ScanInformation.TrufflehogFound = $true
} else {
    Write-Host "completed"
    Write-Host "No trufflehog cache folder found in user's home directory."
    $script:report.ScanInformation.TrufflehogFound = $false
}
Write-Host

# Download list of known affected npm packages
$knownCompromisedNpmPackagesUrl = "https://raw.githubusercontent.com/DataDog/indicators-of-compromise/refs/heads/main/shai-hulud-2.0/consolidated_iocs.csv"
Write-Host "Downloading list of known affected npm packages from $knownCompromisedNpmPackagesUrl ... " -NoNewline
$knownCompromisedNpmPackagesCsv = Invoke-RestMethod -Uri $knownCompromisedNpmPackagesUrl -ErrorAction Stop
$Script:knownCompromisedNpmPackages = $knownCompromisedNpmPackagesCsv | ConvertFrom-Csv
Write-Host "completed"
Write-Host "List included $($knownCompromisedNpmPackages.Count) npm packages."
Write-Host

# File scanning
Write-Host "Note:" -ForegroundColor Yellow
Write-Host "Scanning may take a while depending on the size of the target path and number of files." -ForegroundColor Yellow
Write-Host "Example scanning developer folder with >70k package.json files took ~60 minutes." -ForegroundColor Yellow
Write-Host
Test-Folder -Path $ScanRootPath

if ($globalNpmNodeModulesPath) {
    Test-Folder -Path $globalNpmNodeModulesPath
}

if ($nvmNodeVersionsPath) {
    Test-Folder -Path $nvmNodeVersionsPath
}

Write-Host "+------------+" -ForegroundColor Cyan
Write-Host "|   REPORT   |" -ForegroundColor Cyan
Write-Host "+------------+" -ForegroundColor Cyan
Write-Host

# Update report information
$scanEndTime = Get-Date
$report.ScanInformation.ScanEndTime = $scanEndTime.ToString()
$report.ScanInformation.ScanDuration = ($scanEndTime - $scanStartTime).ToString()
$report.ScanInformation.InfectedFilesFound = $report.InfectedFiles.Count
$report.ScanInformation.SuspectedFilesFound = $report.SuspectedFiles.Count
$report.ScanInformation.NpmPackageWarningsFound = $report.NpmPackageWarnings.Count
$report.ScanInformation.FilesWithScanError = $report.FilesWithScanError.Count

# Store report
$reportFolder = New-Item -Path "./ScanReports/$((Get-Date).ToString('yyyyMMdd_HHmmss'))" -ItemType Directory -Force
$report.InfectedFiles | Export-Csv -Path "$($reportFolder.FullName)/InfectedFiles.csv" -Encoding UTF8 -NoTypeInformation
$report.SuspectedFiles | Export-Csv -Path "$($reportFolder.FullName)/SuspectedFiles.csv" -Encoding UTF8 -NoTypeInformation
$report.NpmPackageWarnings | Export-Csv -Path "$($reportFolder.FullName)/NpmPackageWarnings.csv" -Encoding UTF8 -NoTypeInformation
$report.ScanInformation | ConvertTo-Json -Depth 10 | Out-File -FilePath "$($reportFolder.FullName)/ScanInformation.json" -Encoding UTF8
if ($report.FilesWithScanError.Count -gt 0) {
    $errorFolder = New-Item -Path "$($reportFolder.FullName)/error" -ItemType Directory -Force
    $report.FilesWithScanError | Export-Csv -Path "$($errorFolder.FullName)/FilesWithScanError.csv" -Encoding UTF8 -NoTypeInformation
}

$mayBeSafe = $true
if ($report.ScanInformation.TrufflehogFound) {
    $mayBeSafe = $false
    Write-Host "!!! WARNING: Trufflehog cache folder found in user's home directory !!!" -ForegroundColor Yellow
    Write-Host "Even though Trufflehog is a legitimate tool, this may indicate that the system has been compromised since the tool is used for credential stealing by the worm." -ForegroundColor Yellow
    Write-Host
}

if ($report.ScanInformation.InfectedFilesFound -gt 0) {
    $mayBeSafe = $false
    Write-Host "!!! WARNING: Possibly infected files found !!!" -ForegroundColor Red
    Write-Host "These findings are urgent and should be addressed immediately." -ForegroundColor Red
    Write-Host "Do not run anything that can trigger the preinstall script." -ForegroundColor Red
    Write-Host "Please review the scan report for list of files."
    Write-Host
}

if ($report.ScanInformation.SuspectedFilesFound -gt 0) {
    $mayBeSafe = $false
    Write-Host "!!! WARNING: Files matching known malicious file names found !!!" -ForegroundColor Red
    Write-Host "This is an indication that the system may already be compromised." -ForegroundColor Red
    Write-Host "Please review the scan report for list of files."
    Write-Host
}

if ($report.ScanInformation.NpmPackageWarningsFound -gt 0) {
    $mayBeSafe = $false
    Write-Host "!!! WARNING: References to known compromised npm packages found !!!" -ForegroundColor Red
    Write-Host "Above findings does not necessarily mean infection is pending, but it should be investigated and references should be locked to known safe versions." -ForegroundColor Yellow
    Write-Host "Please review the scan report for details and compare referenced package versions with list of known compromised versions."
    Write-Host
}

if ($mayBeSafe) {
    Write-Host "No signs of Shai-Hulud 2.0 infection detected in this run." -ForegroundColor Green
    Write-Host
}

Write-Host "Scan report saved to: $($reportFolder.FullName)"
Write-Host
Write-Host "Scan completed in $($report.ScanInformation.ScanDuration)."

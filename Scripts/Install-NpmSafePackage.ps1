<#
.SYNOPSIS
    Safely installs npm packages with script execution disabled.
.DESCRIPTION
    Installs packages using --ignore-scripts to prevent malicious code execution.
    NOTE: Some packages (native modules, puppeteer, electron) may not work without their
    postinstall scripts. After verifying safety, run 'npm rebuild <package>' if needed.
.PARAMETER PackageName
    Package name(s) to install (comma-separated). If omitted, installs all dependencies from package.json.
.PARAMETER ProjectPath
    Project directory. Defaults to current directory.
.PARAMETER SaveDev
    Save to devDependencies instead of dependencies.
.EXAMPLE
    .\Install-NpmSafePackage.ps1
    .\Install-NpmSafePackage.ps1 express
    .\Install-NpmSafePackage.ps1 "typescript,eslint" -SaveDev
#>
Param(
    [Parameter(Mandatory=$false, Position=0)]
    [string]$PackageName,
    [string]$ProjectPath = ".",
    [switch]$SaveDev,
    [switch]$SkipScanner
)

function Get-SkippedScripts {
    param([string]$NodeModulesPath)
    
    $packagesWithScripts = @()
    
    Get-ChildItem -Path $NodeModulesPath -Filter "package.json" -Recurse -File | ForEach-Object {
        try {
            $pkg = Get-Content $_.FullName -Raw | ConvertFrom-Json
            $scriptTypes = @()
            if ($pkg.scripts.preinstall) { $scriptTypes += "preinstall" }
            if ($pkg.scripts.install) { $scriptTypes += "install" }
            if ($pkg.scripts.postinstall) { $scriptTypes += "postinstall" }
            
            if ($scriptTypes.Count -gt 0) {
                $packagesWithScripts += [PSCustomObject]@{
                    Package = $pkg.name
                    Version = $pkg.version
                    Scripts = $scriptTypes -join ", "
                }
            }
        } catch {}
    }
    
    return $packagesWithScripts
}

$ProjectPath = (Resolve-Path $ProjectPath).Path

if (-not (Test-Path (Join-Path $ProjectPath "package.json"))) {
    Write-Error "package.json not found in: $ProjectPath"
    exit 1
}

# Run pre-installation security scan
if (-not $SkipScanner) {
    $scannerPath = Join-Path (Split-Path -Parent $PSScriptRoot) "ShaiHuludChecker\Run-ShaiHuludScanner.ps1"
    if (Test-Path $scannerPath) {
        Write-Host "`nRunning pre-installation security scan..." -ForegroundColor Magenta
        & $scannerPath -ScanRootPath $ProjectPath -SkipGlobalNpmPackagesScan
        $scanExitCode = $LASTEXITCODE
        
        # Exit codes: 0=clean, 1=warnings, 2=infected, 3=suspected, 4=trufflehog
        if ($scanExitCode -eq 2 -or $scanExitCode -eq 3) {
            Write-Host "`n!!! CRITICAL: Scanner detected infections or suspected malicious files !!!" -ForegroundColor Red
            Write-Host "Installation ABORTED for safety." -ForegroundColor Red
            exit $scanExitCode
        }
        
        if ($scanExitCode -eq 1 -or $scanExitCode -eq 4) {
            Write-Host "`nWarnings detected. Continue with installation? (y/N): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -ne "y") {
                Write-Host "Installation cancelled by user." -ForegroundColor Red
                exit 1
            }
        }
    } else {
        Write-Warning "Scanner not found at: $scannerPath"
        Write-Host "Continue without pre-scan? (y/N): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -ne "y") {
            exit 1
        }
    }
}

Write-Host "`nInstalling packages with --ignore-scripts (prevents malicious preinstall/postinstall scripts)" -ForegroundColor Yellow

$npmArgs = @("install", "--ignore-scripts")
if ($PackageName) {
    $npmArgs += $PackageName.Split(",") | ForEach-Object { $_.Trim() }
}
if ($SaveDev) { $npmArgs += "--save-dev" }

Push-Location $ProjectPath
try {
    Write-Host "Running: npm $($npmArgs -join ' ')`n" -ForegroundColor Cyan
    npm @npmArgs
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n✓ Installation completed successfully" -ForegroundColor Green
        
        # Scan for packages with skipped scripts
        Write-Host "`nScanning for packages with skipped lifecycle scripts..." -ForegroundColor Cyan
        $skippedPackages = Get-SkippedScripts -NodeModulesPath "node_modules"
        
        # Run post-installation security scan
        if (-not $SkipScanner) {
            $scannerPath = Join-Path (Split-Path -Parent $PSScriptRoot) "ShaiHuludChecker\Run-ShaiHuludScanner.ps1"
            if (Test-Path $scannerPath) {
                Write-Host "`nRunning post-installation security scan..." -ForegroundColor Magenta
                & $scannerPath -ScanRootPath $ProjectPath -SkipGlobalNpmPackagesScan
                $scanExitCode = $LASTEXITCODE
                
                # Exit codes: 0=clean, 1=warnings, 2=infected, 3=suspected, 4=trufflehog
                if ($scanExitCode -eq 2 -or $scanExitCode -eq 3) {
                    Write-Host "`n!!! CRITICAL: Newly installed packages contain infections or malicious files !!!" -ForegroundColor Red
                    Write-Host "Do NOT run npm rebuild or any lifecycle scripts!" -ForegroundColor Red
                    Write-Host "Review scan results and remove compromised packages immediately." -ForegroundColor Red
                    exit $scanExitCode
                } elseif ($scanExitCode -eq 1 -or $scanExitCode -eq 4) {
                    Write-Host "`n⚠ WARNING: Scanner detected issues. Review results above carefully!" -ForegroundColor Yellow
                } else {
                    Write-Host "`n✓ Post-installation scan clean" -ForegroundColor Green
                }
            } else {
                Write-Warning "Scanner not found - Install security may be compromised!"
            }
        } else {
            Write-Warning "Security scanner was skipped - Install has not been validated!"
        }
        
        # Final summary about skipped scripts
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
        Write-Host "INSTALLATION SUMMARY" -ForegroundColor Cyan
        Write-Host ("=" * 70) -ForegroundColor Cyan
        
        if ($skippedPackages.Count -gt 0) {
            Write-Host "`n⚠ PACKAGES WITH SKIPPED LIFECYCLE SCRIPTS ($($skippedPackages.Count)):" -ForegroundColor Yellow
            $skippedPackages | Format-Table Package, Version, Scripts -AutoSize
            
            Write-Host "These packages had their install scripts blocked for security." -ForegroundColor Yellow
            Write-Host "Some packages (native modules, puppeteer, etc.) may not work without them.`n" -ForegroundColor Yellow
            
            Write-Host "TO RUN SCRIPTS AFTER VERIFYING THEY ARE SAFE:" -ForegroundColor Green
            Write-Host "  • Single package:  npm rebuild <package-name>" -ForegroundColor White
            Write-Host "  • All packages:    npm rebuild`n" -ForegroundColor White
        } else {
            Write-Host "`n✓ No packages with lifecycle scripts detected." -ForegroundColor Green
        }
    } else {
        Write-Error "npm install failed with exit code: $LASTEXITCODE"
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

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
    
    if ($packagesWithScripts.Count -gt 0) {
        Write-Host "`n⚠ Found $($packagesWithScripts.Count) package(s) with skipped lifecycle scripts:" -ForegroundColor Yellow
        $packagesWithScripts | Format-Table -AutoSize
        Write-Host "To run scripts after verification: npm rebuild <package-name>`n" -ForegroundColor Yellow
    } else {
        Write-Host "No packages with lifecycle scripts detected.`n" -ForegroundColor Green
    }
}

$ProjectPath = (Resolve-Path $ProjectPath).Path

if (-not (Test-Path (Join-Path $ProjectPath "package.json"))) {
    Write-Error "package.json not found in: $ProjectPath"
    exit 1
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
        Get-SkippedScripts -NodeModulesPath "node_modules"
        
        # Run security scanner if not skipped
        if (-not $SkipScanner) {
            $scannerPath = Join-Path (Split-Path -Parent $PSScriptRoot) "ShaiHuludChecker\Run-ShaiHuludScanner.ps1"
            if (Test-Path $scannerPath) {
                Write-Host "`nRunning security scanner..." -ForegroundColor Magenta
                & $scannerPath -ScanRootPath $ProjectPath -SkipGlobalNpmPackagesScan
            } else {
                Write-Warning "Scanner not found at: $scannerPath"
            }
        }
    } else {
        Write-Error "npm install failed with exit code: $LASTEXITCODE"
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

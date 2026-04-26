# RansomwareDetectPs Auto Build Script
# Simple and reliable build script for all modules
# Supports offline build with local third-party dependencies

$ErrorActionPreference = "Stop"
$scriptPath = $PSScriptRoot

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RansomwareDetectPs Auto Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 离线构建配置
$offlineMode = $true  # 强制离线模式
Write-Host "Build Mode: Offline (using local dependencies)" -ForegroundColor Yellow
Write-Host ""

# 验证本地依赖
Write-Host "Checking local dependencies..." -ForegroundColor Gray
$dependencies = @(
    @{
        Name = "Lua 5.4.7"
        Path = "src\rasp_rule_engine\third_party\lua\src\lua.h"
        Required = $true
    },
    @{
        Name = "PCRE2 10.44"
        Path = "src\rasp_rule_engine\third_party\pcre2\CMakeLists.txt"
        Required = $true
    },
    @{
        Name = "nlohmann/json 3.11.3"
        Path = "src\rasp_sentry_native\third_party\nlohmann\json.hpp"
        Required = $true
    }
)

$allDepsReady = $true
foreach ($dep in $dependencies) {
    $fullPath = Join-Path $scriptPath $dep.Path
    if (Test-Path $fullPath) {
        Write-Host "  ✓ $($dep.Name) - Ready" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($dep.Name) - Missing: $($dep.Path)" -ForegroundColor Red
        if ($dep.Required) {
            $allDepsReady = $false
        }
    }
}

Write-Host ""

if (-not $allDepsReady) {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "ERROR: Missing required dependencies!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please ensure all dependencies are present:" -ForegroundColor Yellow
    Write-Host "  - src\rasp_rule_engine\third_party\lua\src\lua.h" -ForegroundColor White
    Write-Host "  - src\rasp_rule_engine\third_party\pcre2\CMakeLists.txt" -ForegroundColor White
    Write-Host "  - src\rasp_sentry_native\third_party\nlohmann\json.hpp" -ForegroundColor White
    Write-Host ""
    Write-Host "Note: Lua header is in lua/src/ directory, not directly in lua/" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Write-Host "All dependencies verified!" -ForegroundColor Green
Write-Host ""

# Disable git SSL verification (备用，但离线模式不需要)
if (-not $offlineMode) {
    Write-Host "Configuring git SSL verification..." -ForegroundColor Gray
    git config --global http.sslVerify false
} else {
    Write-Host "Skipping git config (offline mode)" -ForegroundColor Gray
}

Write-Host ""

try {
    Write-Host ""
    Write-Host "Building rasp_mod_amsi..." -ForegroundColor Green
    Write-Host "--------------------------------" -ForegroundColor Green
    
    $modulePath = Join-Path $scriptPath "src\rasp_mod_amsi"
    $buildDir = Join-Path $modulePath "build"
    
    # Clean build directory
    if (Test-Path $buildDir) {
        Write-Host "Cleaning build directory..." -ForegroundColor Gray
        Remove-Item -Path $buildDir -Recurse -Force
    }
    
    # Configure with offline settings
    Write-Host "Configuring CMake (offline mode)..." -ForegroundColor Gray
    $cmakeArgs = @(
        "-S", $modulePath,
        "-B", $buildDir,
        "-G", "Visual Studio 17 2022",
        "-A", "x64",
        "-DFETCHCONTENT_UPDATES_DISCONNECTED=ON",  # 离线模式：断开内容更新
        "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"     # 离线模式：完全断开
    )
    & cmake @cmakeArgs
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed" }
    
    # Build
    Write-Host "Building Release..." -ForegroundColor Gray
    cmake --build $buildDir --config Release
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    
    Write-Host "rasp_mod_amsi.dll built successfully!" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Building rasp_sentry_native..." -ForegroundColor Green
    Write-Host "--------------------------------" -ForegroundColor Green
    
    $modulePath = Join-Path $scriptPath "src\rasp_sentry_native"
    $buildDir = Join-Path $modulePath "build"
    
    # Clean build directory
    if (Test-Path $buildDir) {
        Write-Host "Cleaning build directory..." -ForegroundColor Gray
        Remove-Item -Path $buildDir -Recurse -Force
    }
    
    # Configure with offline settings
    Write-Host "Configuring CMake (offline mode)..." -ForegroundColor Gray
    $cmakeArgs = @(
        "-S", $modulePath,
        "-B", $buildDir,
        "-G", "Visual Studio 17 2022",
        "-A", "x64",
        "-DFETCHCONTENT_UPDATES_DISCONNECTED=ON",
        "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"
    )
    & cmake @cmakeArgs
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed" }
    
    # Build
    Write-Host "Building Release..." -ForegroundColor Gray
    cmake --build $buildDir --config Release
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    
    Write-Host "rasp_sentry.exe built successfully!" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "All modules built successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Build output:" -ForegroundColor Yellow
    Write-Host "  rasp_mod_amsi.dll:   src\rasp_mod_amsi\build\Release\" -ForegroundColor Gray
    Write-Host "  rasp_sentry.exe:     src\rasp_sentry_native\build\Release\" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Offline build completed successfully!" -ForegroundColor Green
    Write-Host "No network access was required during build." -ForegroundColor Gray    
} catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Build failed: $_" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
    Write-Host "  1. Verify dependencies: .\check_offline_deps.ps1" -ForegroundColor Cyan
    Write-Host "  2. Clean build: .\clean_build.bat" -ForegroundColor Cyan
    Write-Host "  3. Check build logs for specific errors" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
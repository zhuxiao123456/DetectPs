param(
    [string]$SourceText,
    [string]$SourceFile,
    [string]$OutputBytecode,
    [string]$OutputBase64,
    [string]$BuildDir = "src\rasp_mod_amsi\build-codex",
    [string]$Configuration = "Release",
    [switch]$PrintBase64,
    [switch]$StripDebug
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot

function Resolve-RepoPath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return (Join-Path $RepoRoot $Path)
}

function Find-VcVars64 {
    $candidates = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($installPath) {
            $vcvars = Join-Path $installPath "VC\Auxiliary\Build\vcvars64.bat"
            if (Test-Path -LiteralPath $vcvars) {
                return $vcvars
            }
        }
    }

    return $null
}

function Invoke-WithVcEnv([string]$Command) {
    $cl = Get-Command cl.exe -ErrorAction SilentlyContinue
    if ($cl) {
        cmd.exe /d /c $Command
        if ($LASTEXITCODE -ne 0) {
            throw "command failed with exit code $LASTEXITCODE"
        }
        return
    }

    $vcvars = Find-VcVars64
    if (-not $vcvars) {
        throw "cl.exe was not found. Run from a Visual Studio Developer PowerShell, or install Visual Studio C++ Build Tools."
    }

    cmd.exe /d /c "call `"$vcvars`" >nul && $Command"
    if ($LASTEXITCODE -ne 0) {
        throw "command failed with exit code $LASTEXITCODE"
    }
}

if ([string]::IsNullOrEmpty($SourceText) -and [string]::IsNullOrEmpty($SourceFile)) {
    throw "Specify -SourceText or -SourceFile."
}

if (-not [string]::IsNullOrEmpty($SourceText) -and -not [string]::IsNullOrEmpty($SourceFile)) {
    throw "Specify only one of -SourceText or -SourceFile."
}

$buildRoot = Resolve-RepoPath $BuildDir
$luaInclude = Join-Path $RepoRoot "src\rasp_rule_engine\third_party\lua\src"
$luaLib = Join-Path $buildRoot "rasp_rule_engine\$Configuration\lua54_static.lib"

if (-not (Test-Path -LiteralPath $luaLib)) {
    Write-Host "[convert] building lua54_static in $BuildDir ($Configuration)"
    cmake --build $BuildDir --config $Configuration --target lua54_static
    if ($LASTEXITCODE -ne 0) {
        throw "failed to build lua54_static"
    }
}

if (-not (Test-Path -LiteralPath $luaLib)) {
    throw "lua54_static.lib not found: $luaLib"
}

$workDir = Join-Path $env:TEMP ("rasp_lua_bytecode_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workDir | Out-Null

try {
    $inputPath = Join-Path $workDir "input.lua"
    if ($SourceFile) {
        $resolvedSource = Resolve-RepoPath $SourceFile
        if (-not (Test-Path -LiteralPath $resolvedSource)) {
            throw "source file not found: $resolvedSource"
        }
        Copy-Item -LiteralPath $resolvedSource -Destination $inputPath
    } else {
        [System.IO.File]::WriteAllText($inputPath, $SourceText, [System.Text.UTF8Encoding]::new($false))
    }

    $toolCpp = Join-Path $workDir "lua_bytecode_tool.cpp"
    $toolExe = Join-Path $workDir "lua_bytecode_tool.exe"
    $bytecodePath = if ($OutputBytecode) { Resolve-RepoPath $OutputBytecode } else { Join-Path $workDir "out.luac" }

    $cpp = @'
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}

struct BytecodeWriter {
    std::vector<char> bytes;
};

static int WriteLuaBytecode(lua_State*, const void* data, size_t size, void* userData)
{
    BytecodeWriter* writer = static_cast<BytecodeWriter*>(userData);
    const char* begin = static_cast<const char*>(data);
    writer->bytes.insert(writer->bytes.end(), begin, begin + size);
    return 0;
}

static std::string ReadAll(const char* path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cerr << "usage: lua_bytecode_tool <input.lua> <output.luac> [strip]\n";
        return 2;
    }

    const std::string source = ReadAll(argv[1]);
    if (source.empty()) {
        std::cerr << "input is empty or unreadable\n";
        return 3;
    }

    lua_State* L = luaL_newstate();
    if (!L) {
        std::cerr << "luaL_newstate failed\n";
        return 4;
    }

    if (luaL_loadbuffer(L, source.data(), source.size(), argv[1]) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        std::cerr << "lua compile failed: " << (err ? err : "(null)") << "\n";
        lua_close(L);
        return 5;
    }

    BytecodeWriter writer;
    const int strip = (argc >= 4 && std::string(argv[3]) == "strip") ? 1 : 0;
    if (lua_dump(L, WriteLuaBytecode, &writer, strip) != 0) {
        std::cerr << "lua_dump failed\n";
        lua_close(L);
        return 6;
    }

    lua_close(L);

    std::ofstream out(argv[2], std::ios::binary);
    if (!out) {
        std::cerr << "cannot open output\n";
        return 7;
    }
    out.write(writer.bytes.data(), static_cast<std::streamsize>(writer.bytes.size()));
    if (!out) {
        std::cerr << "write output failed\n";
        return 8;
    }

    std::cout << writer.bytes.size() << "\n";
    return 0;
}
'@
    [System.IO.File]::WriteAllText($toolCpp, $cpp, [System.Text.UTF8Encoding]::new($false))

    $compileCommand = "cl.exe /nologo /EHsc /MD /I`"$luaInclude`" `"$toolCpp`" /Fe`"$toolExe`" `"$luaLib`""
    Invoke-WithVcEnv $compileCommand

    $stripArg = if ($StripDebug) { " strip" } else { "" }
    $runCommand = "`"$toolExe`" `"$inputPath`" `"$bytecodePath`"$stripArg"
    Invoke-WithVcEnv $runCommand

    $bytes = [System.IO.File]::ReadAllBytes($bytecodePath)
    $base64 = [Convert]::ToBase64String($bytes)

    if ($OutputBase64) {
        $base64Path = Resolve-RepoPath $OutputBase64
        [System.IO.File]::WriteAllText($base64Path, $base64, [System.Text.UTF8Encoding]::new($false))
        Write-Host "[convert] base64 written: $base64Path"
    }

    if ($OutputBytecode) {
        Write-Host "[convert] bytecode written: $bytecodePath"
    }

    Write-Host "[convert] bytecode bytes: $($bytes.Length)"
    if ($PrintBase64 -or -not $OutputBase64) {
        $base64
    }
}
finally {
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force
    }
}

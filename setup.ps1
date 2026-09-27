<#
.SYNOPSIS
    环境引导：为本工具准备可用的 Python 环境（cryptography / pycryptodome），并写入 config.json。

.DESCRIPTION
    默认在包内建 .venv 并安装依赖 —— 与系统 Python 隔离，config.json 里写【相对路径】，整包可搬。
    装不上（无网络/被墙）时会自动兜底：若系统里有现成装好依赖的解释器，
    就用 --system-site-packages 重建 .venv（复用它的库，不需要下载）。

    三种模式（-Mode）：
      venv   （默认）使用/创建包内 .venv，并（联网）安装依赖
      auto   系统里已有装好依赖的解释器就直接用它（最快，不建 venv）；没有才建 .venv
      system 只用系统解释器，并把它写进 config.json（注意：这是【该机器专属】的绝对路径）

    收尾会自动跑一遍 push.ps1 -Action Selftest 验收。

.PARAMETER Mode
    venv / auto / system，默认 venv。
.PARAMETER PythonExe
    指定基础解释器（默认自动探测：环境变量 → 包内 .venv → PATH 的 python → py 启动器 → 常见位置）。
.PARAMETER PipIndex
    pip 源。国内网络推荐 http://pypi.tuna.tsinghua.edu.cn/simple（http 可绕开 TLS 问题）。
.PARAMETER PipProxy
    pip 代理，例如 http://127.0.0.1:7897
.PARAMETER Offline
    不联网安装；直接用「系统解释器已有依赖 + --system-site-packages」的方式建 .venv。
.PARAMETER NoMirror
    安装失败时不自动改用清华镜像重试。
.PARAMETER Recreate
    .venv 已存在时删掉重建。
.PARAMETER NoSelftest
    收尾不跑 Selftest。

.EXAMPLE
    .\setup.ps1
.EXAMPLE
    .\setup.ps1 -Offline                      # 没网也能配好（复用系统已装的库）
.EXAMPLE
    .\setup.ps1 -Mode auto                    # 系统里已有可用解释器就直接用
.EXAMPLE
    .\setup.ps1 -PipProxy http://127.0.0.1:7897 -Recreate
#>
[CmdletBinding()]
param(
    [ValidateSet('venv', 'auto', 'system')][string]$Mode = 'venv',
    [string]$PythonExe,
    [string]$PipIndex,
    [string]$PipProxy,
    [switch]$Offline,
    [switch]$NoMirror,
    [switch]$Recreate,
    [switch]$NoSelftest
)

$ErrorActionPreference = 'Stop'
$env:PYTHONIOENCODING = 'utf-8'
$script:StepNo = 0
function Step([string]$m) { $script:StepNo++; Write-Host ('[{0}] {1}' -f $script:StepNo, $m) }
function Info([string]$m) { Write-Host ('    ' + $m) }
function Warn([string]$m) { Write-Host ('    [警告] ' + $m) -ForegroundColor Yellow }
function Fail([string]$m) { Write-Host ('[失败] ' + $m) -ForegroundColor Red; exit 1 }

function Invoke-Native([string]$exe, [string[]]$argv) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $prevEnc = $null
    try { $prevEnc = [Console]::OutputEncoding } catch { }
    try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
    try { $o = & $exe @argv 2>&1 } finally {
        $ErrorActionPreference = $prev
        if ($null -ne $prevEnc) { try { [Console]::OutputEncoding = $prevEnc } catch { } }
    }
    $res = @()
    foreach ($x in @($o)) {
        if ($x -is [System.Management.Automation.ErrorRecord]) { $res += $x.ToString() } else { $res += [string]$x }
    }
    return $res
}
function Get-FirstLine([object]$o) { $a = @($o); if ($a.Count -eq 0) { return '' }; return ([string]$a[0]).Trim() }
# PS 5.1 的 Get-Content 默认按系统 ANSI 读文件：无 BOM 的 UTF-8（含中文/JSON）会乱码甚至解析失败。
# 统一用显式 UTF-8 读（带 BOM 的也能正确识别并剥掉）—— .json 按 R13 必须无 BOM，所以这条必须走显式编码。
function Read-TextFile([string]$p) { return [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8) }
function Get-PyVersion([string]$exe) { return Get-FirstLine (Invoke-Native $exe @('-c', 'import sys; print(sys.version.split()[0])')) }
function Test-PyLibs([string]$exe) {
    if (-not (Test-Path -LiteralPath $exe)) { return $false }
    # 判据只用【退出码】：Python 报 ModuleNotFoundError 时会把源码那一行也回显出来，
    # 拿源码里的字串当成功标记会假阳性（2026-09-27 踩过：3.13/3.14 没装却被判"依赖齐全"）。
    $null = Invoke-Native $exe @('-c', 'import cryptography, Crypto')
    return ($LASTEXITCODE -eq 0)
}
function Get-JsonValue($v) {
    if ($null -eq $v) { return 'null' }
    if ($v -is [bool]) { if ($v) { return 'true' } else { return 'false' } }
    if ($v -is [int] -or $v -is [long] -or $v -is [double]) { return ([string]$v) }
    if ($v -is [System.Array] -or $v -is [System.Collections.IList]) { return '[' + ((@($v) | ForEach-Object { Get-JsonValue $_ }) -join ', ') + ']' }
    return '"' + ([string]$v).Replace('\', '\\').Replace('"', '\"') + '"'
}
function Get-PyCandidates {
    $list = @()
    if ($PythonExe) { $list += $PythonExe }
    if ($env:WECHATDBFIX_PYTHON) { $list += $env:WECHATDBFIX_PYTHON }
    $list += $venvPy
    foreach ($c in @(Get-Command python -All -ErrorAction SilentlyContinue)) { $list += $c.Source }
    foreach ($l in @(Invoke-Native 'py' @('-0p'))) {
        if ($l -match '([A-Za-z]:\\[^\s]+python\.exe)') { $list += $Matches[1] }
    }
    foreach ($pat in @(
            (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\python.exe'),
            (Join-Path $env:ProgramFiles 'Python*\python.exe'),
            'C:\Python*\python.exe')) {
        $list += @(Get-ChildItem -Path $pat -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
    return @($list | Where-Object { $_ } | Select-Object -Unique)
}
# 安装依赖：先默认源，失败后（可选）自动改清华镜像；都失败返回 $false
function Install-Deps([string]$py) {
    $base = @('-m', 'pip', 'install', '--disable-pip-version-check', '--timeout', '15', '--retries', '2', '--only-binary', ':all:')
    $tries = @()
    if ($PipIndex) { $tries += @{ Name = ('指定源 ' + $PipIndex); Args = ($base + @('-i', $PipIndex) + @('cryptography', 'pycryptodome')) } }
    else { $tries += @{ Name = '默认源(PyPI)'; Args = ($base + @('cryptography', 'pycryptodome')) } }
    if (-not $NoMirror -and -not $PipIndex) {
        $tries += @{ Name = '清华镜像(http)'; Args = ($base + @('-i', 'http://pypi.tuna.tsinghua.edu.cn/simple') + @('cryptography', 'pycryptodome')) }
    }
    foreach ($t in $tries) {
        $args = $t.Args
        if ($PipProxy) { $args = $args + @('--proxy', $PipProxy) }
        Info ('尝试：' + $t.Name + $(if ($PipProxy) { '（经代理 ' + $PipProxy + '）' } else { '' }))
        $o = Invoke-Native $py $args
        $ok = ($LASTEXITCODE -eq 0)
        foreach ($l in ($o | Select-Object -Last 4)) { Info ('  ' + $l) }
        if ($ok -and (Test-PyLibs $py)) { return $true }
        Warn ($t.Name + ' 未成功（退出码 ' + $LASTEXITCODE + '）')
    }
    return $false
}

$root = $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $root) { $root = (Get-Location).Path }
$venvDir = Join-Path $root '.venv'
$venvPy = Join-Path $venvDir 'Scripts\python.exe'

Write-Host ('==== 环境引导（Mode=' + $Mode + $(if ($Offline) { ', Offline' } else { '' }) + '）====')
Info ('包目录 = ' + $root)

# ---------- 1. 探测 ----------
Step '探测可用解释器'
$withLibs = @(); $noLibs = @()
foreach ($c in (Get-PyCandidates)) {
    if (-not (Test-Path -LiteralPath $c)) { continue }
    if ($c -eq $venvPy) { continue }          # .venv 稍后单独判
    $v = Get-PyVersion $c
    if ($v -notmatch '^3\.') { Info ('  跳过（不是 Python 3）：' + $c); continue }
    if (Test-PyLibs $c) { $withLibs += $c; Info ('  ✓ 依赖齐全  ' + $c + '  (Python ' + $v + ')') }
    else { $noLibs += $c; Info ('  ✗ 缺依赖    ' + $c + '  (Python ' + $v + ')') }
}
$venvOk = Test-PyLibs $venvPy
if (Test-Path -LiteralPath $venvPy) { Info ('  ' + $(if ($venvOk) { '✓' } else { '✗' }) + ' 包内 .venv  ' + $venvPy + '  (Python ' + (Get-PyVersion $venvPy) + ')') }
if ($withLibs.Count -eq 0 -and $noLibs.Count -eq 0 -and -not (Test-Path -LiteralPath $venvPy)) {
    Fail '没找到任何 Python 3 解释器。请先安装 Python 3.7+（https://www.python.org/downloads/，勾选 Add python.exe to PATH），或用 -PythonExe 指定。'
}
$base = ''
if ($PythonExe) { $base = $PythonExe }
elseif ($withLibs.Count -gt 0) { $base = $withLibs[0] }
elseif ($noLibs.Count -gt 0) { $base = $noLibs[0] }
elseif (Test-Path -LiteralPath $venvPy) { $base = $venvPy }
$baseHasLibs = ($base -ne '' -and (Test-PyLibs $base))

# ---------- 2. 选定方案 ----------
$useVenv = $false
$pick = ''
if ($Mode -eq 'venv') { $useVenv = $true }
elseif ($Mode -eq 'auto') {
    if ($venvOk) { $pick = $venvPy; $useVenv = $false }
    elseif ($withLibs.Count -gt 0) { $pick = $withLibs[0]; $useVenv = $false }
    else { $useVenv = $true }
} else {
    if ($withLibs.Count -eq 0) {
        Warn 'system 模式要求现成装好依赖的解释器，但没有找到。可先执行（然后重跑本脚本）：'
        foreach ($c in $noLibs) { Info ('  "' + $c + '" -m pip install cryptography pycryptodome javaobj-py3') }
        Fail '已停止。'
    }
    $pick = $withLibs[0]
    $useVenv = $false
}

# ---------- 3. 建/用 venv 或直接用系统解释器 ----------
$cfgValue = ''
$fpMode = $false        # 是否用了 --system-site-packages 兜底
if ($useVenv) {
    if ($venvOk -and -not $Recreate) {
        Step '包内 .venv 已可用，直接复用'
        Info ($venvPy + '  (Python ' + (Get-PyVersion $venvPy) + ')')
    } else {
        if ($Recreate -and (Test-Path -LiteralPath $venvDir)) {
            Step '.venv 已存在：按 -Recreate 删除重建'
            $removed = $false
            for ($i = 1; $i -le 5; $i++) {
                try { Remove-Item -LiteralPath $venvDir -Recurse -Force -ErrorAction Stop; $removed = $true; break }
                catch { Start-Sleep -Milliseconds 800 }
            }
            if (-not $removed) {
                # 多半是还有 python/pip 进程占用（例如上一次安装卡死留下的）
                $moved = '.venv-old-' + (Get-Date -Format 'HHmmss')
                try {
                    Rename-Item -LiteralPath $venvDir -NewName $moved -ErrorAction Stop
                    Info ('删不掉（被进程占用），已改名挪走：' + $moved + '（可稍后手动删除）')
                } catch {
                    Fail '.venv 既删不掉也挪不走，很可能被进程占用：请在任务管理器结束占用它的 python/pythonw（路径含 .venv\Scripts\python.exe），再重跑本脚本。'
                }
            }
        }
        if (-not (Test-Path -LiteralPath $venvDir)) {
            $args = @('-m', 'venv')
            if ($Offline -and $baseHasLibs) { $args += '--system-site-packages' }
            $args += $venvDir
            Step ('创建包内虚拟环境（基础解释器：' + $base + $(if ($Offline -and $baseHasLibs) { '，--system-site-packages 复用其库' } else { '' }) + '）')
            $o = Invoke-Native $base $args
            foreach ($l in ($o | Select-Object -Last 4)) { Info $l }
            if (-not (Test-Path -LiteralPath $venvPy)) { Fail ('创建 .venv 失败：' + ($o -join ' / ')) }
            Info ('已创建：' + $venvPy)
        }
    }
    if (-not (Test-PyLibs $venvPy)) {
        if ($Offline) {
            Warn '按 -Offline 跳过联网安装'
        } else {
            Step '安装依赖到 .venv'
            $installed = Install-Deps $venvPy
            if (-not $installed) {
                Warn '联网安装失败（无网络/被墙）。尝试离线兜底：用 --system-site-packages 复用系统解释器已有的库'
            }
        }
        if (-not (Test-PyLibs $venvPy)) {
            # 离线兜底
            if ($baseHasLibs) {
                Step ('重建 .venv（--system-site-packages，复用 ' + $base + ' 的库，不需要下载）')
                if (Test-Path -LiteralPath $venvDir) { Remove-Item -LiteralPath $venvDir -Recurse -Force }
                $o = Invoke-Native $base @('-m', 'venv', '--system-site-packages', $venvDir)
                foreach ($l in ($o | Select-Object -Last 3)) { Info $l }
                $fpMode = $true
            }
            if (-not (Test-PyLibs $venvPy)) {
                Warn '依赖仍不可用。三条出路：'
                Info '  ① 联网后重跑：.\setup.ps1 -Recreate'
                Info '  ② 走代理/镜像：.\setup.ps1 -Recreate -PipProxy http://127.0.0.1:7897'
                Info '                  .\setup.ps1 -Recreate -PipIndex http://pypi.tuna.tsinghua.edu.cn/simple'
                Info '  ③ 用已有可用的系统解释器：.\setup.ps1 -Mode auto'
                Fail '环境未就绪，已停止。'
            }
        }
    }
    $chosen = $venvPy
    $cfgValue = '.venv/Scripts/python.exe'
    if ($fpMode) {
        Warn '.venv 用的是 --system-site-packages（依赖来自基础解释器，基础解释器被卸载/升级后需重跑本脚本）'
    }
} else {
    $chosen = $pick
    $cfgValue = $pick
    Step '选择现有解释器（不建 venv）'
    Info ('使用：' + $chosen)
    Warn '会把该解释器的【绝对路径】写进 config.json —— 这份配置只对本机有效；想让整包换台机器照样能用，请用默认的 -Mode venv'
}

Step '验收：导入依赖'
if (-not (Test-PyLibs $chosen)) { Fail ('所选解释器仍缺依赖：' + $chosen) }
Info ('cryptography + pycryptodome 就绪：' + $chosen)

# ---------- 4. 写 config.json（保留其它键）----------
Step '写入 config.json'
$cfgPath = Join-Path $root 'config.json'
$obj = [ordered]@{}
$src = ''
if (Test-Path -LiteralPath $cfgPath) { $src = $cfgPath }
elseif (Test-Path -LiteralPath (Join-Path $root 'config.example.json')) { $src = Join-Path $root 'config.example.json' }
if ($src) {
    $j = Read-TextFile $src | ConvertFrom-Json
    foreach ($p in $j.PSObject.Properties) { if ($p.Name -ne 'PythonExe') { $obj[$p.Name] = $p.Value } }
    Info ('基于已有配置：' + (Split-Path $src -Leaf))
}
$obj['PythonExe'] = $cfgValue
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine('{')
$keys = @($obj.Keys)
for ($i = 0; $i -lt $keys.Count; $i++) {
    $tail = ','
    if ($i -eq $keys.Count - 1) { $tail = '' }
    $null = $sb.AppendLine('  "' + $keys[$i] + '": ' + (Get-JsonValue $obj[$keys[$i]]) + $tail)
}
$null = $sb.AppendLine('}')
[System.IO.File]::WriteAllText($cfgPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding $false))
Info ('PythonExe = ' + $cfgValue)
Info ('已写入：' + $cfgPath + '（无 BOM）')

# ---------- 5. Selftest 验收 ----------
if (-not $NoSelftest) {
    Step '验收：push.ps1 -Action Selftest'
    $push = Join-Path $root 'push.ps1'
    if (Test-Path -LiteralPath $push) {
        $o = Invoke-Native 'powershell' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $push, '-Action', 'Selftest')
        foreach ($l in ($o | Select-Object -Last 6)) { Info $l }
        if (($o -join "`n") -match '本地自检通过') { Info 'Selftest 通过 ✓' } else { Warn 'Selftest 未通过，请看上面输出' }
    } else { Warn ('没找到 ' + $push + '，跳过验收') }
}

Write-Host ''
Info '环境就绪。之后直接用：.\push.ps1 -Action Auto'

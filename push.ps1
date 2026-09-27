<#
.SYNOPSIS
    微信 EnMicroMsg.db 手机端脚本：拉取（含 WAL 合并）→ 处理（调用 build.ps1）→ 推回手机，含备份与回滚。

.DESCRIPTION
    动作（-Action）：
      Status     只读：设备/微信版本/数据库路径/大小/权限/SELinux 上下文/剩余空间/root 方式/待推入产物
      Backup     只读手机：把 EnMicroMsg.db / -wal / -shm 拉到 phone-backups\<时间戳>\；若 -wal 非空则合并出主库并校验
      Push       写手机：把 <ProjectRoot>\output\EnMicroMsg.db 推回手机（先备份 → 替换 → 修权限 → 双向校验 → 看 logcat）
      RoundTrip  写手机：Backup → 解密手机当前库 → 调用 build.ps1 合并数据 → Push
      Rollback   写手机：把最近一次备份的主库推回手机（出问题的退路）
      Selftest   不需要手机：在 TEMP 里自检本地工具链（WAL 合并 / 加密 / 解密 / 处理脚本在不在）

    安全设计：
      · 除 Selftest 外都先检查设备与 root；写操作默认要人工确认（-Yes 跳过），支持 -DryRun 只打印不执行
      · 任何写操作前必定先做完整备份（拉三件套到电脑 + 设备内再留 .bak/.bak-wal）；
        拉取必须走 /data/local/tmp 中转：adb pull 是 shell 身份，读不了 /data/data，得先用 root 把文件
        复制出来、chmod 644，再 pull，最后删掉中转文件；
        Backup 默认先 force-stop 微信以保证快照一致（-NoStopApp 可跳过，但一致性自负）
      · 替换用 cp 覆盖同名文件（保留 inode → 天然保住 owner/mode/SELinux 上下文），并显式再套一遍原属性
      · 推完做 md5 双向核对；随后清 logcat、启动微信、抓关键词（corrupt / EnMicroMsg / sqlite / WCDB）
      · WAL 语义：-wal 里"已提交"的帧按 SQLite 规则逐页并入主库（帧内容与主库同为密文，纯搬运，
        无需解密），合并后立刻解密 + integrity_check 验证；不通过就退回"不合并"版本并告警

    重要：
    首次请按 Status → Backup →（确认备份无误）→ Push 的顺序来，不要一上来就 RoundTrip。

    前置条件：adb 可用；手机已 root 且已授权；微信已安装；Python 已装 cryptography。

.PARAMETER Action
    见上。默认 Status（最安全）。
.PARAMETER AdbExe
    adb 路径。依次尝试：随包 tools\adb.exe → PATH → 常见安装位置（也可用环境变量 WECHATDBFIX_ADB 指定）
.PARAMETER ProjectRoot
    项目根目录。默认本脚本所在目录。
.PARAMETER DbFile
    Push 要推入的加密库。默认 <ProjectRoot>\output\EnMicroMsg.db
.PARAMETER WxDb
    手机上的 EnMicroMsg.db 完整路径（多个账号目录时用来指定用哪一个）。
.PARAMETER SourceDb
    RoundTrip 的数据来源明文库。默认 data\source-plain.db
.PARAMETER BackupRoot
    备份根目录。默认 <ProjectRoot>\phone-backups
.PARAMETER BackupDir
    Rollback 用：指定回滚到哪次备份（默认最近一次）。
.PARAMETER Key
    7 位密钥。不填则从手机拉来的 auth_info_key_prefs.xml 反推，并用手机库验证。
.PARAMETER WaitSeconds
    启动微信后等多久再抓日志。默认 25 秒。
.PARAMETER DryRun
    写操作只打印计划，不真正执行。
.PARAMETER Yes
    跳过人工确认（脚本化场景；请自行确认备份已存在）。
.PARAMETER KeepTemp
    保留 TEMP 工作目录。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\push.ps1 -Action Selftest
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\push.ps1 -Action Status
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\push.ps1 -Action Backup
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\push.ps1 -Action Push -DryRun
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\push.ps1 -Action RoundTrip
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\push.ps1 -Action Rollback
#>
[CmdletBinding()]
param(
    [ValidateSet('Status', 'Backup', 'Push', 'RoundTrip', 'Auto', 'Rollback', 'Selftest')]
    [string]$Action = 'Status',
    [string]$AdbExe,
    [string]$ProjectRoot,
    [string]$Config,
    [string]$DbFile,
    [string]$WxDb,
    [string]$SourceDb = 'auto',
    [string[]]$SourceDir,
    [string[]]$SourceName = @('EnMicroMsg.db', 'decrypted_EnMicroMsg.db'),
    [switch]$SourceRecurse,
    [string]$BackupRoot,
    [string]$BackupDir,
    [string]$Key,
    [string]$Imei = '1234567890ABCDEF',
    [string]$PythonExe = 'python',
    [string]$SqliteExe,
    [string]$Encryptor,
    [string]$Decryptor,
    [string]$Processor,
    [int]$WaitSeconds = 25,
    [switch]$DryRun,
    [switch]$Yes,
    [string]$ExpectVersion = '',
    [switch]$AnyVersion,
    [switch]$NoStopApp,
    [switch]$KeepTemp
)

$ErrorActionPreference = 'Stop'
$env:PYTHONIOENCODING = 'utf-8'
$script:StepNo = 0
# Auto = RoundTrip 的"接线到结束"版：自动找数据源、自动定密钥、自验通过后直接推送（不再询问）。
# 省略的只是"确认"这一步，强制备份 / 版本守卫 / md5 校验 / 回滚保护一样不少。
if ($Action -eq 'Auto') { $Yes = $true }
$script:RootMode = 'none'
$script:WxDir = ''
$script:WxDb = ''

function Step([string]$m) { $script:StepNo++; Write-Host ('[{0}] {1}' -f $script:StepNo, $m) }
function Info([string]$m) { Write-Host ('    ' + $m) }
function Warn([string]$m) { Write-Host ('    [警告] ' + $m) -ForegroundColor Yellow }
function Fail([string]$m) { Write-Host ('[失败] ' + $m) -ForegroundColor Red; exit 1 }
function MaskKey([string]$k) { if (-not $k) { return '(未设置)' }; return $k.Substring(0, 3) + ('*' * [Math]::Max(1, $k.Length - 3)) }

function Invoke-Native([string]$exe, [string[]]$argv) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    # 外部程序（python/adb）的输出多是 UTF-8；PowerShell 5.1 默认按控制台代码页（中文系统=GBK）解码，
    # 于是中文输出会变成"涓诲簱…"这种乱码。这里临时把控制台输出编码切成 UTF-8，读完再还原。
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
function Sha256([string]$p) { return (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash }
function Md5([string]$p) { return (Get-FileHash -Algorithm MD5 -LiteralPath $p).Hash.ToLower() }
function Get-HeaderBytes([string]$p) {
    $fs = [System.IO.File]::OpenRead($p)
    $b = New-Object byte[] 32
    $null = $fs.Read($b, 0, 32)
    $fs.Close()
    return $b
}
# 数据库操作只允许作用于 TEMP 工作副本（事故教训：绝不把 sqlite 类工具指向项目内原件）
function Assert-Work([string]$p) {
    if (-not $work) { Fail '内部错误：TEMP 工作目录尚未初始化' }
    if (-not $p.StartsWith($work, [StringComparison]::OrdinalIgnoreCase)) {
        Fail ('安全拦截：试图对工作区之外的文件执行数据库操作：' + $p)
    }
}
function Invoke-Sqlite([string]$db, [string]$sql) {
    Assert-Work $db
    return Invoke-Native $SqliteExe @($db, $sql)
}

# ---------- 配置文件（优先级：命令行 > 配置文件 > 内置默认）----------
$cfgRoot = $PSScriptRoot
if (-not $cfgRoot) { $cfgRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $cfgRoot) { $cfgRoot = (Get-Location).Path }
$cfgPath = $Config
if (-not $cfgPath) { $cfgPath = Join-Path $cfgRoot 'config.json' }
$cfg = @{}
if (Test-Path -LiteralPath $cfgPath) {
    try {
        $json = Read-TextFile $cfgPath | ConvertFrom-Json
        foreach ($prop in $json.PSObject.Properties) {
            $v = $prop.Value
            if ($null -eq $v) { continue }
            if (($v -is [string]) -and ($v -eq '')) { continue }   # 空串 = 用内置默认
            $cfg[$prop.Name] = $v
        }
        Write-Host ('已读取配置：' + $cfgPath)
    } catch {
        Warn ('配置文件解析失败，已忽略：' + $cfgPath + ' —— ' + $_.Exception.Message)
    }
} elseif ($Config) {
    Fail ('-Config 指定的配置文件不存在：' + $cfgPath)
}
$cfgSwitchKeys = @('AnyVersion', 'NoStopApp', 'KeepTemp', 'SourceRecurse', 'DryRun', 'Yes')
$cfgKnownKeys = @(
    'AdbExe', 'ProjectRoot', 'DbFile', 'WxDb', 'SourceDb', 'SourceDir', 'SourceName', 'SourceRecurse',
    'BackupRoot', 'BackupDir', 'Key', 'Imei', 'PythonExe', 'SqliteExe', 'Decryptor', 'Encryptor',
    'Processor', 'WaitSeconds', 'ExpectVersion', 'AnyVersion', 'NoStopApp', 'KeepTemp',
    'BaseDb', 'OutDir', 'KeyXml', 'KeyCheckDb', 'ExtraExclude'
)
foreach ($k in $cfgKnownKeys) {
    if ($PSBoundParameters.ContainsKey($k)) { continue }   # 命令行给了就优先
    if (-not $cfg.ContainsKey($k)) { continue }
    if ($cfgSwitchKeys -contains $k) { Set-Variable -Name $k -Value ([bool]$cfg[$k]) -Scope Script }
    else { Set-Variable -Name $k -Value $cfg[$k] -Scope Script }
    Write-Host ('  配置生效：' + $k + ' = ' + ($cfg[$k] -join ' / '))
}
# ---------- 环境变量（覆盖配置文件，但低于命令行）----------
$envMap = [ordered]@{ AdbExe = 'WECHATDBFIX_ADB'; PythonExe = 'WECHATDBFIX_PYTHON'; SqliteExe = 'WECHATDBFIX_SQLITE'; Decryptor = 'WECHATDBFIX_DECRYPTOR'; Encryptor = 'WECHATDBFIX_ENCRYPTOR'; Processor = 'WECHATDBFIX_PROCESSOR'; KeyXml = 'WECHATDBFIX_KEY_XML'; Key = 'WECHATDBFIX_KEY'; Imei = 'WECHATDBFIX_IMEI'; DbFile = 'WECHATDBFIX_DB_FILE'; WxDb = 'WECHATDBFIX_WX_DB'; SourceDb = 'WECHATDBFIX_SOURCE_DB'; SourceDir = 'WECHATDBFIX_SOURCE_DIR'; SourceName = 'WECHATDBFIX_SOURCE_NAME'; BackupRoot = 'WECHATDBFIX_BACKUP_ROOT'; ExpectVersion = 'WECHATDBFIX_EXPECT_VERSION' }
foreach ($k in $envMap.Keys) {
    if ($PSBoundParameters.ContainsKey($k)) { continue }
    $ev = [Environment]::GetEnvironmentVariable($envMap[$k])
    if ([string]::IsNullOrWhiteSpace($ev)) { continue }
    if ($k -eq 'SourceDir' -or $k -eq 'SourceName') {
        Set-Variable -Name $k -Value @($ev -split ';' | Where-Object { $_ -ne '' }) -Scope Script
    } else {
        Set-Variable -Name $k -Value $ev -Scope Script
    }
    Write-Host ('  环境变量生效：' + $k + ' = ' + $ev)
}

# 找 adb：随包 tools\adb.exe → PATH → 常见安装位置（都可用环境变量 WECHATDBFIX_ADB 覆盖）
function Find-AdbPath {
    $cands = @()
    if ($ProjectRoot) { $cands += (Join-Path $ProjectRoot 'tools\adb.exe') }
    if ($env:LOCALAPPDATA) { $cands += (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe') }
    if ($env:USERPROFILE) { $cands += (Join-Path $env:USERPROFILE 'platform-tools\adb.exe') }
    if ($env:ProgramFiles) { $cands += (Join-Path $env:ProgramFiles 'platform-tools\adb.exe') }
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    $g = Get-Command adb -ErrorAction SilentlyContinue
    if ($g) { return $g.Source }
    return ''
}
# ---------- 路径解析 ----------
$root = $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $root) { $root = (Get-Location).Path }
if (-not $ProjectRoot) { $ProjectRoot = $root }
if (-not $DbFile)      { $DbFile = Join-Path $ProjectRoot 'output\EnMicroMsg.db' }
if (-not $SourceDir -or $SourceDir.Count -eq 0) {
    # 数据源搜索目录：默认这几个，可用 -SourceDir 或配置文件覆盖（业务路径不写死在逻辑里）
    $SourceDir = @('data', 'data-src', '.')
}
# 相对路径一律按项目根解析（配置文件里写相对路径也能用）
$SourceDir = @($SourceDir | ForEach-Object { if ([System.IO.Path]::IsPathRooted($_)) { $_ } else { Join-Path $ProjectRoot $_ } })
if (-not $BackupRoot)  { $BackupRoot = Join-Path $ProjectRoot 'phone-backups' }
if (-not $SqliteExe)   { $SqliteExe = Join-Path $ProjectRoot 'tools\sqlite3.exe' }
if (-not $Decryptor)   { $Decryptor = Join-Path $ProjectRoot 'tools\wechat_decrypt.py' }
if (-not $Processor)   { $Processor = Join-Path $ProjectRoot 'build.ps1' }
if (-not $Encryptor) {
    $encCand = @(@((Join-Path $ProjectRoot 'tools\wechat_encrypt.py'), (Join-Path $ProjectRoot 'wechat_encrypt.py')) | Where-Object { Test-Path -LiteralPath $_ })
    if ($encCand.Count -gt 0) { $Encryptor = [string]$encCand[0] } else { $Encryptor = Join-Path $ProjectRoot 'tools\wechat_encrypt.py' }
}
if (-not $AdbExe) { $AdbExe = Find-AdbPath }
$script:Adb = $AdbExe
# 配置/环境变量里给的相对路径（例如 .venv/Scripts/python.exe）：按包目录解析成绝对路径，
# 裸命令名（如 python）仍交给 PATH 查找。
foreach ($vn in @('PythonExe', 'SqliteExe', 'Decryptor', 'Encryptor', 'Processor')) {
    $vv = [string](Get-Variable -Name $vn -ValueOnly)
    if (-not $vv) { continue }
    if ($vn -eq 'PythonExe' -and $vv -notmatch '[\\/]') { continue }
    if (-not [System.IO.Path]::IsPathRooted($vv)) {
        $rc = Join-Path $ProjectRoot $vv
        if (Test-Path -LiteralPath $rc) { Set-Variable -Name $vn -Value $rc -Scope Script }
    }
}


$work = Join-Path $env:TEMP ('wxpush-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host ('==== 微信 EnMicroMsg.db 手机端脚本（Action=' + $Action + '）====')
Info "adb      = $AdbExe"
Info "项目根   = $ProjectRoot"

# ---------- 内嵌 Python 工具：WAL 合并 ----------
$walMergePath = Join-Path $work 'walmerge.py'
$walMergeSrc = @'
#!/usr/bin/env python3
# SQLite WAL 合并器（微信 EnMicroMsg.db 用）：把 WAL 中"已提交"的帧并入主库。
#
# 为什么可以不解密就搬运：WAL 帧里的页内容与主库页是同一套密文格式（微信/SQLCipher 无 HMAC 布局，
# 每页自带的 IV 就在该页末尾 16 字节里），所以按页号整页搬运即可 —— 这正是 SQLite checkpoint 的语义。
#
# 校验规则（照 sqlite wal.c 的恢复规则实现，不是"看着像就搬"）：
#   1) WAL 头 magic ∈ {0x377f0682(小端校验和), 0x377f0683(大端)}，头部自身校验和必须对得上
#   2) 逐帧读：帧盐必须等于 WAL 头盐、帧校验和（覆盖"帧头前 8 字节 + 页内容"，携带前一帧的运行校验和）
#      必须对得上；一旦不符就立刻停止 —— 后面是上一代遗留的陈旧帧，绝不能当有效帧用
#   3) 只采纳最后一个"提交帧"及之前的帧；提交帧声明的页数写回主库头部（偏移 28），
#      并把文件长度对齐到 页数×页大小（WAL 会把库写大，也可能写小）
#   4) 主库若是加密库（头部为密文），读不出页大小 —— 此时以 WAL 头声明的页大小为准
#
# 已验证：与 SQLite 自己的 checkpoint 结果【逐字节一致】（合成库基准测试）。
#
# 用法: python walmerge.py <主库> <wal> <输出主库>
# 退出码: 0=成功或无需合并; 2=WAL 与主库不匹配（magic/页大小/头部校验和）
import sys
import struct

WAL_HDR = 32
FRAME_HDR = 24
VALID_PSZ = (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)


def checksum(native, data, s1, s2):
    """SQLite walChecksumBytes：data 长度取 8 的整数倍"""
    n = len(data) - (len(data) % 8)
    for i in range(0, n, 8):
        if native:
            x = (data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]
            y = (data[i + 4] << 24) | (data[i + 5] << 16) | (data[i + 6] << 8) | data[i + 7]
        else:
            x = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
            y = data[i + 4] | (data[i + 5] << 8) | (data[i + 6] << 16) | (data[i + 7] << 24)
        s1 = (s1 + x + s2) & 0xFFFFFFFF
        s2 = (s2 + y + s1) & 0xFFFFFFFF
    return s1, s2


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    db, wal, out = sys.argv[1], sys.argv[2], sys.argv[3]
    d = bytearray(open(db, 'rb').read())
    w = open(wal, 'rb').read()
    is_plain = bytes(d[:16]) == b'SQLite format 3\x00'

    def finish(msg):
        print(msg)
        open(out, 'wb').write(bytes(d))
        return 0

    if len(w) < WAL_HDR + FRAME_HDR:
        return finish('WAL 过短，视为无有效帧，原样输出')

    magic, ver, psz, ckpt, salt1, salt2, h1, h2 = struct.unpack('>8I', w[:WAL_HDR])
    if magic not in (0x377f0682, 0x377f0683):
        print('WAL magic 异常：0x%08x' % magic)
        return 2
    if psz == 1:
        psz = 65536
    if psz not in VALID_PSZ:
        print('WAL 头声明的页大小不合理：%d' % psz)
        return 2
    if is_plain:
        db_page = struct.unpack('>H', bytes(d[16:18]))[0]
        if db_page == 1:
            db_page = 65536
        if psz != db_page:
            print('WAL 页大小 %d 与明文主库页大小 %d 不一致' % (psz, db_page))
            return 2
    else:
        print('主库非明文（加密库），按 WAL 头声明的页大小 %d 处理' % psz)

    native = 1 if (magic & 1) else 0
    c1, c2 = checksum(native, w[0:24], 0, 0)
    if (c1, c2) != (h1, h2):
        print('WAL 头部校验和不符，拒绝合并')
        return 2

    frame_size = FRAME_HDR + psz
    total = (len(w) - WAL_HDR) // frame_size
    s1, s2 = h1, h2
    valid = []
    stopped = ''
    for i in range(total):
        off = WAL_HDR + i * frame_size
        hdr = w[off:off + 8]
        fs1, fs2 = struct.unpack('>2I', w[off + 8:off + 16])
        st1, st2 = struct.unpack('>2I', w[off + 16:off + 24])
        if fs1 != salt1 or fs2 != salt2:
            stopped = '第 %d 帧盐不符（上一代遗留），到此为止' % (i + 1)
            break
        s1, s2 = checksum(native, hdr, s1, s2)
        s1, s2 = checksum(native, w[off + FRAME_HDR:off + frame_size], s1, s2)
        if (s1, s2) != (st1, st2):
            stopped = '第 %d 帧校验和不符（其后为陈旧帧），到此为止' % (i + 1)
            break
        valid.append((off, struct.unpack('>2I', hdr)))

    if not valid:
        return finish('WAL 无有效帧（%s），原样输出' % (stopped if stopped else '总帧数 0'))

    last_commit = -1
    for idx, (off, (pgno, dbsize)) in enumerate(valid):
        if dbsize != 0:
            last_commit = idx
    if last_commit < 0:
        return finish('WAL 有效帧 %d 个但都未提交，原样输出' % len(valid))

    applied = 0
    distinct = set()
    final_size = 0
    for idx in range(last_commit + 1):
        off, (pgno, dbsize) = valid[idx]
        if dbsize != 0:
            final_size = dbsize
        if pgno == 0:
            continue
        pos = (pgno - 1) * psz
        need = pos + psz
        if need > len(d):
            d.extend(b'\x00' * (need - len(d)))
        d[pos:need] = w[off + FRAME_HDR:off + frame_size]
        applied += 1
        distinct.add(pgno)

    if final_size > 0:
        d[28:32] = struct.pack('>I', final_size)
        want = final_size * psz
        if len(d) > want:
            del d[want:]
        elif len(d) < want:
            d.extend(b'\x00' * (want - len(d)))

    msg = 'WAL 总帧 %d，有效帧 %d（%s）；已并入 %d 帧 / %d 页' % (
        total, len(valid), stopped if stopped else '全部有效', applied, len(distinct))
    if final_size > 0:
        msg += '；头部页数写为 %d' % final_size
    return finish(msg)


if __name__ == '__main__':
    sys.exit(main())
'@
[System.IO.File]::WriteAllText($walMergePath, $walMergeSrc, (New-Object System.Text.UTF8Encoding $false))

# ---------- 设备交互 ----------
function Assert-Adb {
    if ($script:Adb -and (Test-Path -LiteralPath $script:Adb)) { return }
    $g = Get-Command adb -ErrorAction SilentlyContinue
    if ($g) { $script:Adb = $g.Source; return }
    Fail '找不到 adb。任选一种：① 把 adb.exe 放进 tools\ 目录；② 让 adb 在 PATH 里；③ 设环境变量 WECHATDBFIX_ADB=<adb.exe 路径>；④ 用 -AdbExe 指定。'
}
function Get-Device {
    $lines = @(Invoke-Native $script:Adb @('devices'))
    $dev = @()
    foreach ($l in $lines) {
        if ($l -match '^(\S+)\s+device$') { $dev += $Matches[1] }
        elseif ($l -match '^(\S+)\s+unauthorized') { Warn ('设备 ' + $Matches[1] + ' 未授权：先在手机上允许 USB 调试；若手机处于 MTP（文件传输）模式仍显示未授权，把 USB 用途改成「不传输数据 / 仅充电」再试') }
        elseif ($l -match '^(\S+)\s+offline') { Warn ('设备 ' + $Matches[1] + ' 处于 offline') }
    }
    if ($dev.Count -eq 0) { Fail '没有检测到已连接的设备（adb devices 为空）。请插上数据线并在手机上允许 USB 调试；部分机型（MTP / 文件传输模式）会显示未授权，把 USB 用途改成「不传输数据 / 仅充电」即可。' }
    if ($dev.Count -gt 1) { Fail ('检测到多台设备：' + ($dev -join '、') + '。请只保留一台。') }
    return $dev[0]
}
function Get-RootMode {
    $id = Get-FirstLine (Invoke-Native $script:Adb @('shell', 'id'))
    if ($id -match 'uid=0') { return 'shell' }
    $t = (Invoke-Native $script:Adb @('shell', "su -c 'id'")) -join ' '
    if ($t -match 'uid=0') { return 'su' }
    $t2 = (Invoke-Native $script:Adb @('shell', "su 0 sh -c 'id'")) -join ' '
    if ($t2 -match 'uid=0') { return 'su0' }
    return 'none'
}
# 设备侧命令包装：内层单引号（5.1 与 7 都保留；内层双引号会被 5.1 吃掉）。
# 因此 $cmd 内部不得出现单引号 —— 命令里不要给路径加引号，stat 用逗号格式串。
function Invoke-Device([string]$cmd) {
    if ($cmd.Contains("'")) { Fail ('内部错误：设备命令不允许包含单引号：' + $cmd) }
    switch ($script:RootMode) {
        'shell' { return Invoke-Native $script:Adb @('shell', $cmd) }
        'su'    { return Invoke-Native $script:Adb @('shell', ("su -c '" + $cmd + "'")) }
        'su0'   { return Invoke-Native $script:Adb @('shell', ("su 0 sh -c '" + $cmd + "'")) }
        default { Fail '设备上没有 root。本脚本需要 root（读写 /data/data/com.tencent.mm）。' }
    }
}
# 找手机上的微信库：**只认文件名 EnMicroMsg.db**。
# 多个账号目录都含该文件时，取【修改时间最新】的那个（=当前在用的账号），并把候选全列出来；
# 要指定别的：-WxDb <完整路径>，或配置 WxDb / 环境变量 WECHATDBFIX_WX_DB。
function Get-WxInfo {
    if ($WxDb) {
        $sz = Get-FirstLine (Invoke-Device ('stat -c %s ' + $WxDb + ' 2>/dev/null'))
        if ($sz -notmatch '^\d+$') { Fail ('-WxDb 指定的手机库不存在或读不到：' + $WxDb) }
        $script:WxDb = $WxDb
        $i = $WxDb.LastIndexOf('/')
        $script:WxDir = $WxDb.Substring(0, $i + 1)
        Info ('手机库（-WxDb 指定）= ' + $script:WxDb + '  (' + $sz + ' 字节)')
        return [pscustomobject]@{ Dir = $script:WxDir; Db = $script:WxDb; Size = [int64]$sz; Mtime = 0 }
    }
    $out = @(Invoke-Device 'ls -d /data/data/com.tencent.mm/MicroMsg/*/ 2>/dev/null')
    $cands = @()
    foreach ($l in $out) {
        $p = $l.Trim()
        if ($p -notmatch '/MicroMsg/[0-9a-fA-F]{32}/$') { continue }
        $db = $p + 'EnMicroMsg.db'
        $line = Get-FirstLine (Invoke-Device ('stat -c %s,%Y ' + $db + ' 2>/dev/null'))
        if ($line -match '^(\d+),(\d+)$') {
            $cands += [pscustomobject]@{ Dir = $p; Db = $db; Size = [int64]$Matches[1]; Mtime = [int64]$Matches[2] }
        }
    }
    if ($cands.Count -eq 0) {
        Fail '没找到名为 EnMicroMsg.db 的文件（确认微信已登录过、root 可用；或用 -WxDb 指定完整路径）'
    }
    $sorted = @($cands | Sort-Object -Property Mtime -Descending)
    if ($sorted.Count -gt 1) {
        Warn ('有 ' + $sorted.Count + ' 个账号目录都含 EnMicroMsg.db，按【修改时间最新】取当前在用的那个：')
        foreach ($c in $sorted) {
            $mark = ''
            if ($c.Db -eq $sorted[0].Db) { $mark = '   ← 选它' }
            Info ('  ' + $c.Db + '  ' + $c.Size + ' 字节' + $mark)
        }
        Info '  要指定别的账号：-WxDb <完整路径>（或配置 WxDb / 环境变量 WECHATDBFIX_WX_DB）'
    }
    $script:WxDir = $sorted[0].Dir
    $script:WxDb = $sorted[0].Db
    Info ('手机库 = ' + $script:WxDb + '  (' + $sorted[0].Size + ' 字节)')
    return $sorted[0]
}
function Get-RemoteStat([string]$remote) {
    $o = Invoke-Device ('stat -c %s,%u,%g,%a ' + $remote + ' 2>/dev/null')
    $l = Get-FirstLine $o
    if ($l -notmatch '^\d+,\d+,\d+,\d+$') { return $null }
    $p = @($l.Split(','))
    return [pscustomobject]@{ Size = [int64]$p[0]; Uid = $p[1]; Gid = $p[2]; Mode = $p[3] }
}
function Get-RemoteContext([string]$remote) {
    $o = Invoke-Device ('ls -Z ' + $remote + ' 2>/dev/null')
    $l = Get-FirstLine $o
    if ($l -match '^(\S+:\S+:\S+:\S+)') { return $Matches[1] }
    return ''
}
function Get-RemoteFreeKb {
    $o = @(Invoke-Device 'df -k /data')
    for ($i = $o.Count - 1; $i -ge 0; $i--) {
        $f = @(([string]$o[$i]).Trim() -split '\s+')
        if ($f.Count -ge 4 -and $f[3] -match '^\d+$') { return [int64]$f[3] }
    }
    return -1
}
function Confirm-Do([string]$what) {
    if ($DryRun) { Info ('[DryRun] 将执行：' + $what); return $false }
    if ($Yes) { Info ('[已确认 -Yes] ' + $what); return $true }
    Write-Host ''
    Write-Host ('即将执行写手机操作：' + $what) -ForegroundColor Yellow
    $a = Read-Host '确认请输入 yes（其他任意键取消）'
    if ($a -ne 'yes') { Warn '用户取消，未做任何写入'; return $false }
    return $true
}

# ---------- 备份 ----------
# 关键：adb pull 以 shell 身份运行，读不了 /data/data/...（会报 Permission denied）。
# 必须先用 root 把文件复制到 /data/local/tmp（shell 可读），chmod 644，再 pull，最后删掉中转文件。
function Copy-From-Device([string]$remote, [string]$local) {
    $tmp = '/data/local/tmp/wxbak-' + (Split-Path $remote -Leaf)
    $cp = Get-FirstLine (Invoke-Device ('cp -f ' + $remote + ' ' + $tmp + ' && chmod 644 ' + $tmp + ' && echo COPIED; restorecon ' + $tmp + ' 2>/dev/null'))
    if ($cp -notmatch 'COPIED') { return [pscustomobject]@{ Ok = $false; Msg = ('root 复制失败：' + $cp); RemoteMd5 = ''; LocalMd5 = '' } }
    $rmd5 = ''
    $m = Get-FirstLine (Invoke-Device ('md5sum ' + $tmp))
    if ($m -match '^([0-9a-fA-F]{32})') { $rmd5 = $Matches[1].ToLower() }
    $o = Invoke-Native $script:Adb @('pull', $tmp, $local)
    $null = Invoke-Device ('rm -f ' + $tmp)
    if (-not (Test-Path -LiteralPath $local)) { return [pscustomobject]@{ Ok = $false; Msg = ('pull 失败：' + (($o | Select-Object -Last 3) -join ' ')); RemoteMd5 = $rmd5; LocalMd5 = '' } }
    return [pscustomobject]@{ Ok = $true; Msg = ''; RemoteMd5 = $rmd5; LocalMd5 = (Md5 $local) }
}

function Invoke-Backup {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dir = Join-Path $BackupRoot $stamp
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Step ('备份到 ' + $dir)
    if (-not $NoStopApp) {
        Info '先 force-stop 微信：保证拷贝期间它不在写库（快照一致）。不想停就加 -NoStopApp'
        $null = Invoke-Device 'am force-stop com.tencent.mm'
        Start-Sleep -Seconds 2
    } else { Warn '按 -NoStopApp 跳过了 force-stop（微信可能正在写库，快照一致性自负）' }
    $plan = @()
    foreach ($f in @($script:WxDb, ($script:WxDb + '-wal'), ($script:WxDb + '-shm'))) {
        $sz = Get-FirstLine (Invoke-Device ('stat -c %s ' + $f + ' 2>/dev/null'))
        if ($sz -notmatch '^\d+$') { $plan += [pscustomobject]@{ Remote = $f; Name = (Split-Path $f -Leaf); Size = -1 } }
        else { $plan += [pscustomobject]@{ Remote = $f; Name = (Split-Path $f -Leaf); Size = [int64]$sz } }
    }
    $maxSize = 0
    foreach ($p in $plan) { if ($p.Size -gt $maxSize) { $maxSize = $p.Size } }
    $free = Get-RemoteFreeKb
    if ($free -ge 0 -and $maxSize -gt 0) {
        $need = [int64]($maxSize / 1024) + 20480
        if ($free -lt $need) { Fail ('手机 /data 空间不足：可用 ' + $free + ' KB，中转需要约 ' + $need + ' KB') }
        Info ('/data 可用 ' + $free + ' KB（中转需要约 ' + $need + ' KB）')
    }
    foreach ($p in $plan) {
        if ($p.Size -lt 0) { Info ('不存在，跳过：' + $p.Name); continue }
        if ($p.Size -eq 0) { Info ('大小为 0，跳过：' + $p.Name); continue }
        $local = Join-Path $dir $p.Name
        $r = Copy-From-Device $p.Remote $local
        if (-not $r.Ok) { Fail ($p.Name + ' —— ' + $r.Msg) }
        $mark = '  (未取到手机端 md5)'
        if ($r.RemoteMd5 -ne '') {
            if ($r.RemoteMd5 -eq $r.LocalMd5) { $mark = '  md5 一致 ✓' }
            else { Fail ($p.Name + ' 的 md5 不一致：手机 ' + $r.RemoteMd5 + ' / 本地 ' + $r.LocalMd5) }
        }
        Info ('{0,-18} {1,12:N0} 字节  sha256={2}{3}' -f $p.Name, (Get-Item -LiteralPath $local).Length, (Sha256 $local), $mark)
    }
    $dbLocal = Join-Path $dir 'EnMicroMsg.db'
    $walLocal = Join-Path $dir 'EnMicroMsg.db-wal'
    if ((Test-Path -LiteralPath $walLocal) -and (Test-Path -LiteralPath $dbLocal)) {
        Step 'WAL 合并（把已提交帧并入主库，还原手机当前真实状态）'
        $merged = Join-Path $dir 'EnMicroMsg.db+wal 合并.db'
        $o = Invoke-Native $PythonExe @($walMergePath, $dbLocal, $walLocal, $merged)
        foreach ($l in $o) { Info $l }
        if ((Test-Path -LiteralPath $merged) -and (Get-Item -LiteralPath $merged).Length -gt 0) {
            if ((Md5 $merged) -eq (Md5 $dbLocal)) { Info '合并结果与主库相同（该 WAL 无可并入的提交）' }
            else { Info ('合并库 sha256=' + (Sha256 $merged)) }
        }
    }
    return $dir
}

# ---------- 密钥 ----------
function Get-KeyFromPhone([string]$dir, [string]$encDb) {
    if ($Key) { Info ('使用 -Key 指定：' + (MaskKey $Key)); return $Key }
    Step '从手机拉 auth_info_key_prefs.xml 并反推密钥'
    $xmlRemote = '/data/data/com.tencent.mm/shared_prefs/auth_info_key_prefs.xml'
    $xmlLocal = Join-Path $dir 'auth_info_key_prefs.xml'
    $r = Copy-From-Device $xmlRemote $xmlLocal
    if (-not $r.Ok) { Fail ('拉取 auth_info_key_prefs.xml 失败（' + $r.Msg + '），请用 -Key 手工指定密钥') }
    $xml = Read-TextFile $xmlLocal
    $uins = @([regex]::Matches($xml, '\d{8,12}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    if ($uins.Count -eq 0) { Fail 'xml 里找不到 uin，请用 -Key 手工指定密钥' }
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $keys = @()
    foreach ($u in $uins) {
        $h = ($md5.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Imei + $u)) | ForEach-Object { $_.ToString('x2') }) -join ''
        $keys += $h.Substring(0, 7)
    }
    $md5.Dispose()
    $keys = @($keys | Select-Object -Unique)
    $probe = Join-Path $work 'keyprobe.db'
    foreach ($k in $keys) {
        if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Force }
        $null = Invoke-Native $PythonExe @($Decryptor, $encDb, '--key', $k, '-o', $probe, '--quiet')
        if (-not (Test-Path -LiteralPath $probe)) { continue }
        $ic = Get-FirstLine (Invoke-Native $SqliteExe @($probe, 'PRAGMA integrity_check;'))
        $tc = Get-FirstLine (Invoke-Native $SqliteExe @($probe, "SELECT count(*) FROM sqlite_master WHERE type='table';"))
        $okCount = $false
        if ($tc -match '^\d+$') { if ([int]$tc -gt 100) { $okCount = $true } }
        if ($ic -eq 'ok' -and $okCount) { Info ('密钥 = ' + (MaskKey $k) + '（用手机库验证通过）'); return $k }
    }
    Fail '所有候选密钥都解不开手机库，请用 -Key 手工指定'
}

# ---------- 数据来源自动识别 / 版本守卫 ----------
function Get-PhoneVersion {
    return Get-FirstLine (Invoke-Device 'dumpsys package com.tencent.mm | grep -m1 versionName')
}
# 版本号归一化：只取数字，于是 8.0.48 与 8048 被视为同一个版本
function Normalize-Version([string]$v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return '' }
    return ($v -replace '[^0-9]', '')
}
# 目标版本守卫：默认【不检查】（ExpectVersion 留空即关闭）；填了才校验，两种写法等价。
function Assert-TargetVersion {
    $v = Get-PhoneVersion
    Info ('手机微信版本 = ' + $v)
    if ($AnyVersion) { Warn '按 -AnyVersion 跳过了目标版本检查'; return }
    $want = Normalize-Version $ExpectVersion
    if (-not $want) { Info '（未设置 -ExpectVersion，不做目标版本检查）'; return }
    $have = Normalize-Version $v
    if ($have -notlike ('*' + $want + '*')) {
        Fail ('这台手机的微信是 ' + $v + '，与 -ExpectVersion 指定的 ' + $ExpectVersion + '（归一化为 ' + $want + '）不符，已中止。确认要推这台：加 -AnyVersion，或 -ExpectVersion ' + $v)
    }
}
function Get-KeyCandidatesFromXml([string[]]$xmlPaths) {
    $keys = @()
    foreach ($p in $xmlPaths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $x = Read-TextFile $p
        $uins = @([regex]::Matches($x, '\d{8,12}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
        if ($uins.Count -eq 0) { continue }
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $h = @()
        foreach ($u in $uins) {
            $hh = ($md5.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Imei + $u)) | ForEach-Object { $_.ToString('x2') }) -join ''
            $h += $hh.Substring(0, 7)
        }
        $md5.Dispose()
        $keys += $h
        Info ('  从 ' + (Split-Path $p -Leaf) + ' 反推 ' + $h.Count + ' 个候选（' + (Split-Path $p -Parent) + '）')
    }
    return @($keys | Select-Object -Unique)
}
function Test-KeyFor([string]$encDb, [string]$k) {
    # 判据只用 integrity_check：绝不信解密器的"✓ 解密成功"（它对错密钥也这么报）
    $out = Join-Path $work ('kt_' + $k + '.db')
    if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force }
    $null = Invoke-Native $PythonExe @($Decryptor, $encDb, '--key', $k, '-o', $out, '--quiet')
    if (-not (Test-Path -LiteralPath $out)) { return $false }
    $ok = ((Get-FirstLine (Invoke-Sqlite $out 'PRAGMA integrity_check;')) -eq 'ok')
    Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    return $ok
}
function Resolve-KeyFor([string]$encDb) {
    if ($Key) {
        if (Test-KeyFor $encDb $Key) { Info ('用 -Key 指定的密钥（已用 integrity_check 验证）'); return $Key }
        Warn '-Key 指定的密钥解不开这个库，继续尝试自动反推'
    }
    $xmls = @()
    $xmls += (Join-Path $ProjectRoot 'auth_info_key_prefs.xml')
    if (Test-Path -LiteralPath $BackupRoot) {
        $xmls += @(Get-ChildItem -LiteralPath $BackupRoot -Recurse -Filter 'auth_info_key_prefs.xml' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | ForEach-Object { $_.FullName })
    }
    foreach ($k in (Get-KeyCandidatesFromXml $xmls)) {
        if (Test-KeyFor $encDb $k) { Info ('自动反推的密钥 ' + (MaskKey $k) + ' 验证通过 ✓'); return $k }
    }
    return ''
}
# 把候选库变成可用的明文来源：明文直接取，加密的自动反推密钥解密；一律用 integrity_check 验证。
function ConvertTo-SourcePlain([string]$cand, [string]$plain) {
    if (Test-Path -LiteralPath $plain) { Remove-Item -LiteralPath $plain -Force }
    $b = Get-HeaderBytes $cand
    $magic = -join ($b[0..15] | ForEach-Object { [char]$_ })
    if ($magic -eq 'SQLite format 3') {
        Info ('  明文：' + $cand)
        Copy-Item -LiteralPath $cand -Destination $plain -Force
    } else {
        Info ('  加密：' + $cand + '  → 自动反推密钥')
        $k = Resolve-KeyFor $cand
        if (-not $k) { Warn ('  解不开，换下一个候选：' + $cand); return '' }
        $null = Invoke-Native $PythonExe @($Decryptor, $cand, '--key', $k, '-o', $plain, '--quiet')
        if (-not (Test-Path -LiteralPath $plain)) { Warn ('  解密失败，换下一个候选：' + $cand); return '' }
    }
    $ic = Get-FirstLine (Invoke-Sqlite $plain 'PRAGMA integrity_check;')
    if ($ic -ne 'ok') { Warn ('  integrity_check=' + $ic + '，换下一个候选：' + $cand); return '' }
    $tb = Get-FirstLine (Invoke-Sqlite $plain "SELECT count(*) FROM sqlite_master WHERE type='table';")
    $ms = Get-FirstLine (Invoke-Sqlite $plain 'SELECT count(*) FROM message;')
    $mt = Get-FirstLine (Invoke-Sqlite $plain "SELECT datetime(max(createTime)/1000,'unixepoch','localtime') FROM message;")
    Info ('  ✓ 采用：表=' + $tb + '  message=' + $ms + '  最新消息=' + $mt)
    return $plain
}

# 找数据来源：**按文件名**在**配置的目录**里找（目录与文件名都可用参数覆盖，业务路径不写死在逻辑里）。
# 同名多份取修改时间最新的；加密的自动解密；候选不过关就顺着往下试。
function Resolve-SourcePlain {
    $plain = Join-Path $work 'source_plain.db'
    if (Test-Path -LiteralPath $plain) { Remove-Item -LiteralPath $plain -Force }

    if ($SourceDb -and $SourceDb -ne 'auto') {
        if (-not (Test-Path -LiteralPath $SourceDb)) { Fail ('-SourceDb 指定的文件不存在：' + $SourceDb) }
        Info ('数据来源（-SourceDb 指定）：' + $SourceDb)
        $r = ConvertTo-SourcePlain $SourceDb $plain
        if (-not $r) { Fail ('-SourceDb 指定的库不可用：' + $SourceDb) }
        return $r
    }

    Info ('按文件名找数据源：' + ($SourceName -join ' / '))
    Info ('搜索目录：' + (($SourceDir | Where-Object { Test-Path -LiteralPath $_ }) -join ' / ') + $(if ($SourceRecurse) { '（含子目录）' } else { '' }))
    $anyHit = 0
    foreach ($name in $SourceName) {
        $hits = @()
        foreach ($d in $SourceDir) {
            if (-not (Test-Path -LiteralPath $d)) { continue }
            if ($SourceRecurse) {
                $hits += @(Get-ChildItem -LiteralPath $d -Recurse -File -Filter $name -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
            } else {
                $hits += @(Get-ChildItem -LiteralPath $d -File -Filter $name -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
            }
        }
        $hits = @($hits | Select-Object -Unique)
        if ($hits.Count -eq 0) { continue }
        $anyHit += $hits.Count
        Info ('  名为 ' + $name + ' 的有 ' + $hits.Count + ' 个，按修改时间新→旧依次试')
        foreach ($h in @($hits | Sort-Object { (Get-Item -LiteralPath $_).LastWriteTime } -Descending)) {
            $r = ConvertTo-SourcePlain $h $plain
            if ($r) { return $r }
        }
    }
    if ($anyHit -eq 0) {
        Fail ('在搜索目录里没找到名为 ' + ($SourceName -join ' / ') + ' 的文件。用 -SourceDb <文件> 直接指定，或用 -SourceDir <目录…> / -SourceName <文件名…> / -SourceRecurse 调整搜索范围。')
    }
    Fail '找到的候选都不可用（解不开或校验不通过）。用 -SourceDb <文件> 直接指定。'
}

# ---------- 推入 ----------
function Push-Db([string]$localDb, [string]$backupDir, [string]$label, [switch]$SkipVersionCheck) {
    if (-not (Test-Path -LiteralPath $localDb)) { Fail "找不到要推入的库：$localDb" }
    $len = (Get-Item -LiteralPath $localDb).Length
    if ($len % 1024 -ne 0) { Fail "要推入的库大小不是 1024 的整数倍：$len" }
    $b = Get-HeaderBytes $localDb
    if ((-join ($b[0..15] | ForEach-Object { [char]$_ })) -eq 'SQLite format 3') { Fail '要推入的库是明文！请先加密，否则微信会报数据损坏' }

    if (-not $SkipVersionCheck) { Assert-TargetVersion }
    $st = Get-RemoteStat $script:WxDb
    if (-not $st) { Fail '读不到手机上现有库的属性（stat 失败）' }
    $ctx = Get-RemoteContext $script:WxDb
    $free = Get-RemoteFreeKb
    $need = [int64](($len / 1024) * 2 + 20480)
    if ($free -ge 0) {
        if ($free -lt $need) { Fail ("手机 /data 空间不足：可用 $free KB，需要约 $need KB") }
        Info ("手机 /data 可用 $free KB，需要约 $need KB")
    } else { Warn '读不到 /data 可用空间，跳过空间检查' }
    Info ('现有库：' + $st.Size + ' 字节  uid:gid=' + $st.Uid + ':' + $st.Gid + ' mode=' + $st.Mode + ' ctx=' + $(if ($ctx) { $ctx } else { '(未取到)' }))
    Info ('待推入：' + $len + ' 字节  ' + $label + '  md5=' + (Md5 $localDb))

    $remoteTmp = '/data/local/tmp/wxpush-EnMicroMsg.db'
    $remoteBak = $script:WxDb + '.bak-before-push'
    $shName = '/data/local/tmp/wxpush.sh'
    $shLocal = Join-Path $work 'wxpush.sh'
    $lines = @()
    $lines += '#!/system/bin/sh'
    $lines += 'DB="' + $script:WxDb + '"'
    $lines += 'TMP="' + $remoteTmp + '"'
    $lines += 'BAK="' + $remoteBak + '"'
    $lines += 'EXPECT=' + $len
    $lines += 'am force-stop com.tencent.mm'
    $lines += 'sleep 1'
    $lines += 'cp -f "$DB" "$BAK" || { echo RESULT=FAIL-bak; exit 1; }'
    $lines += 'cp -f "$DB-wal" "$BAK-wal" 2>/dev/null'
    $lines += 'rm -f "$DB-wal" "$DB-shm" "$DB-journal"'
    $lines += 'cp -f "$TMP" "$DB" || { echo RESULT=FAIL-cp; exit 1; }'
    $lines += 'NOW=$(stat -c %s "$DB")'
    $lines += 'if [ "$NOW" != "$EXPECT" ]; then echo "RESULT=FAIL-size $NOW"; exit 1; fi'
    if ($ctx) { $lines += 'chcon "' + $ctx + '" "$DB" 2>/dev/null || restorecon "$DB" 2>/dev/null' }
    else { $lines += 'restorecon "$DB" 2>/dev/null' }
    $lines += 'chown ' + $st.Uid + ':' + $st.Gid + ' "$DB" || echo WARN=chown'
    $lines += 'chmod ' + $st.Mode + ' "$DB" || echo WARN=chmod'
    $lines += 'rm -f "$TMP"'
    $lines += 'echo "--- result ---"'
    $lines += 'stat -c "size=%s,uid=%u,gid=%g,mode=%a" "$DB"'
    $lines += 'md5sum "$DB"'
    $lines += 'ls -Z "$DB"'
    $lines += 'echo RESULT=OK'
    [System.IO.File]::WriteAllText($shLocal, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding $false))

    Info '将执行（手机上）：force-stop 微信 → 设备内留 .bak → 删 -wal/-shm → cp 覆盖新库 → 恢复 SELinux 上下文/owner/mode → 校大小与 md5'
    if (-not (Confirm-Do ('把 ' + $localDb + ' 推入 ' + $script:WxDb + '（' + $len + ' 字节）'))) { return $false }

    Step '推送到 /data/local/tmp'
    $o = Invoke-Native $script:Adb @('push', $localDb, $remoteTmp)
    $rtSize = Get-FirstLine (Invoke-Device ('stat -c %s ' + $remoteTmp))
    if ($rtSize -ne ([string]$len)) { Fail ('临时文件大小不符：手机 ' + $rtSize + ' / 本地 ' + $len + '（push 可能失败）') }
    $null = Invoke-Native $script:Adb @('push', $shLocal, $shName)
    Step '执行设备内替换脚本'
    $out = Invoke-Device ('sh ' + $shName)
    foreach ($l in $out) { Info $l }
    $joined = ($out -join "`n")
    if ($joined -notmatch 'RESULT=OK') { Fail '设备内脚本未报 OK（见上面输出）。手机上可能已处于半完成状态，请用 -Action Rollback 回滚。' }
    $remoteMd5 = ''
    foreach ($l in $out) { if ($l -match '^\s*([0-9a-fA-F]{32})\s') { $remoteMd5 = $Matches[1].ToLower() } }
    $localMd5 = (Md5 $localDb).ToLower()
    if ($remoteMd5 -eq '') { Warn '没解析到手机端 md5，请手工核对' }
    elseif ($remoteMd5 -eq $localMd5) { Info 'md5 双向一致 ✓' }
    else { Fail ('md5 不一致：本地 ' + $localMd5 + ' / 手机 ' + $remoteMd5 + '。请立即 -Action Rollback') }
    $null = Invoke-Device ('rm -f ' + $shName)
    return $true
}
function Watch-Logcat([string]$backupDir) {
    Step ('清 logcat、启动微信、等 ' + $WaitSeconds + ' 秒后抓日志')
    $null = Invoke-Native $script:Adb @('logcat', '-c')
    $null = Invoke-Native $script:Adb @('shell', 'am start -n com.tencent.mm/.ui.LauncherUI')
    Start-Sleep -Seconds $WaitSeconds
    $log = Join-Path $backupDir ('logcat-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
    $o = @(Invoke-Native $script:Adb @('logcat', '-d', '-t', '1500'))
    [System.IO.File]::WriteAllText($log, (($o -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding $true))
    $hits = @($o | Where-Object { $_ -match 'EnMicroMsg|corrupt|sqlite|WCDB|MicroMsgDb|database' })
    Info ('日志已存：' + $log)
    if ($hits.Count -eq 0) { Info '未发现 corrupt / EnMicroMsg 相关报错（好迹象）' }
    else {
        Warn ('发现 ' + $hits.Count + ' 行相关日志，末尾 12 行：')
        foreach ($h in ($hits | Select-Object -Last 12)) { Write-Host ('      ' + $h) }
    }
}
function Get-KeyLocal {
    # 本地反推密钥（Selftest 用）：用项目内的加密原件验证
    if ($Key) { return $Key }
    $xml = Join-Path $ProjectRoot 'auth_info_key_prefs.xml'
    if (-not (Test-Path -LiteralPath $xml)) { return '' }
    $checkDb = ''
    foreach ($c in @((Join-Path $ProjectRoot 'data\8048TmpDb\EnMicroMsg.db'), (Join-Path $ProjectRoot 'data\8078TmpDb\EnMicroMsg.db'))) {
        if (Test-Path -LiteralPath $c) { $checkDb = $c; break }
    }
    if (-not $checkDb) { return '' }
    $xmlTxt = Read-TextFile $xml
    $uins = @([regex]::Matches($xmlTxt, '\d{8,12}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $probe = Join-Path $work 'k.db'
    $found = ''
    foreach ($u in $uins) {
        $h = ($md5.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Imei + $u)) | ForEach-Object { $_.ToString('x2') }) -join ''
        $k = $h.Substring(0, 7)
        if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Force }
        $null = Invoke-Native $PythonExe @($Decryptor, $checkDb, '--key', $k, '-o', $probe, '--quiet')
        if (Test-Path -LiteralPath $probe) {
            if ((Get-FirstLine (Invoke-Native $SqliteExe @($probe, 'PRAGMA integrity_check;'))) -eq 'ok') { $found = $k; break }
        }
    }
    $md5.Dispose()
    return $found
}

# ---------- 各动作 ----------
switch ($Action) {

    'Selftest' {
        Step '本地工具链自检（不需要手机）'
        foreach ($p in @($SqliteExe, $Decryptor, $Encryptor, $Processor, $walMergePath)) {
            if (-not (Test-Path -LiteralPath $p)) { Fail "缺少文件：$p" }
            Info ('存在：' + $p)
        }
        $py = Get-FirstLine (Invoke-Native $PythonExe @('-c', 'import sys;print(sys.version.split()[0])'))
        if ($LASTEXITCODE -ne 0) { Fail "python 不可用：$py" }
        $null = Invoke-Native $PythonExe @('-c', 'import cryptography')
        if ($LASTEXITCODE -ne 0) { Fail 'python 缺少 cryptography' }
        Info ('python ' + $py + ' / cryptography OK')

        Step 'WAL 合并自检（用项目内的 8078 加密库 + 其 -wal）'
        $t = Join-Path $work 'wal'
        New-Item -ItemType Directory -Force -Path $t | Out-Null
        $srcDb = Join-Path $ProjectRoot 'data\8078TmpDb\EnMicroMsg.db'
        $srcWal = Join-Path $ProjectRoot 'data\8078TmpDb\EnMicroMsg.db-wal'
        if (-not (Test-Path -LiteralPath $srcDb)) { Warn '项目内没有 data\8078TmpDb\EnMicroMsg.db，跳过 WAL 自检' }
        else {
            $dbCopy = Join-Path $t 'db'
            $merged = Join-Path $t 'db+wal'
            Copy-Item -LiteralPath $srcDb -Destination $dbCopy -Force
            if (Test-Path -LiteralPath $srcWal) {
                $walCopy = Join-Path $t 'db-wal'
                Copy-Item -LiteralPath $srcWal -Destination $walCopy -Force
                $o = Invoke-Native $PythonExe @($walMergePath, $dbCopy, $walCopy, $merged)
                foreach ($l in $o) { Info $l }
                Info ('合并库与原库字节相同：' + ((Md5 $merged) -eq (Md5 $dbCopy)))
                $selK = Get-KeyLocal
                if (-not $selK) { Warn '没推出密钥，跳过"合并结果可否解密"的验证' }
                else {
                    $mp = Join-Path $t 'merged.plain.db'
                    $null = Invoke-Native $PythonExe @($Decryptor, $merged, '--key', $selK, '-o', $mp, '--quiet')
                    $mic = ''
                    if (Test-Path -LiteralPath $mp) { $mic = Get-FirstLine (Invoke-Native $SqliteExe @($mp, 'PRAGMA integrity_check;')) }
                    if ($mic -eq 'ok') { Info '合并结果解密后 integrity_check = ok ✓（该 -wal 与主库同代，可用）' }
                    else { Warn ('合并结果解密后 integrity_check = ' + $mic + ' —— 这份 -wal 与主库不同代（现实里确实会遇到）。RoundTrip 会自动退回未合并版本，不会把坏库推上手机') }
                }
            } else { Warn '没有 -wal 文件，只验证"无 WAL 时原样输出"'; Copy-Item -LiteralPath $dbCopy -Destination $merged -Force }
        }
        Step '加密 → 解密 往返自检（用 8048 起点库）'
        $baseDb = Join-Path $ProjectRoot 'data\base-plain.db'
        if (-not (Test-Path -LiteralPath $baseDb)) { Warn '没有 8048 起点库，跳过往返自检' }
        else {
            $k = Get-KeyLocal
            if (-not $k) { Warn '没推出密钥，跳过往返自检' }
            else {
                Info ('密钥 = ' + (MaskKey $k))
                $enc = Join-Path $t 'enc.db'
                $dec = Join-Path $t 'dec.db'
                $o = Invoke-Native $PythonExe @($Encryptor, 'encrypt', $baseDb, $enc, $k)
                foreach ($l in $o) { Info $l }
                $null = Invoke-Native $PythonExe @($Decryptor, $enc, '--key', $k, '-o', $dec, '--quiet')
                $cmpPy = Join-Path $work 'cmp.py'
                $cmpSrc = "import sys`na=open(sys.argv[1],'rb').read()`nb=open(sys.argv[2],'rb').read()`nP=1024;R=16`nif len(a)!=len(b):`n    print('SIZE'); raise SystemExit(1)`nd=0`nfor p in range(len(a)//P):`n    s=p*P; e=s+P-R`n    if a[s:e]!=b[s:e]: d+=sum(1 for i in range(s,e) if a[i]!=b[i])`nprint(d)`n"
                [System.IO.File]::WriteAllText($cmpPy, $cmpSrc, (New-Object System.Text.UTF8Encoding $false))
                $diff = Get-FirstLine (Invoke-Native $PythonExe @($cmpPy, $baseDb, $dec))
                if ($diff -eq '0') { Info '往返内容区差异 = 0 ✓' } else { Fail ('往返比对不一致：差异 ' + $diff + ' 字节') }
            }
        }
        Step '数据源识别自检（按文件名在配置目录里找，含自动解密与 integrity_check 校验）'
        $anySrc = $false
        foreach ($n in $SourceName) {
            foreach ($d in $SourceDir) {
                if (-not (Test-Path -LiteralPath $d)) { continue }
                if (@(Get-ChildItem -LiteralPath $d -File -Filter $n -ErrorAction SilentlyContinue).Count -gt 0) { $anySrc = $true }
            }
        }
        if (-not $anySrc) {
            Warn ('没找到名为 ' + ($SourceName -join ' / ') + ' 的数据源（把高版本库放进 ' + ($SourceDir -join ' 或 ') + '，或用 -SourceDb 指定）—— 本项跳过')
        } else {
            $srcPick = Resolve-SourcePlain
            Info ('  将使用：' + $srcPick)
        }
        Info '本地自检通过。'
    }

    'Status' {
        Assert-Adb
        Step '设备'
        $dev = Get-Device
        Info ('设备 = ' + $dev)
        Info ('型号 = ' + (Get-FirstLine (Invoke-Native $script:Adb @('shell', 'getprop ro.product.model'))))
        Info ('安卓 = ' + (Get-FirstLine (Invoke-Native $script:Adb @('shell', 'getprop ro.build.version.release'))))
        $script:RootMode = Get-RootMode
        if ($script:RootMode -eq 'none') { Fail '设备上没有 root（su 不可用）。本脚本需要 root。' }
        Info ('root 方式 = ' + $script:RootMode)
        Step '微信'
        Info ('版本 = ' + (Get-FirstLine (Invoke-Device 'dumpsys package com.tencent.mm | grep -m1 versionName')))
        $info = Get-WxInfo
        Info ('数据库目录 = ' + $script:WxDir)
        Info ('数据库     = ' + $script:WxDb + '  (' + $info.Size + ' 字节)')
        foreach ($suffix in @('-wal', '-shm')) {
            $sz = Get-FirstLine (Invoke-Device ('stat -c %s ' + $script:WxDb + $suffix + ' 2>/dev/null'))
            if ($sz -match '^\d+$') { Info ('  ' + $suffix + ' = ' + $sz + ' 字节') } else { Info ('  ' + $suffix + ' 不存在') }
        }
        $st = Get-RemoteStat $script:WxDb
        if ($st) { Info ('权限 = uid:gid ' + $st.Uid + ':' + $st.Gid + '  mode=' + $st.Mode) }
        $ctx = Get-RemoteContext $script:WxDb
        if ($ctx) { Info ('SELinux = ' + $ctx) }
        $free = Get-RemoteFreeKb
        if ($free -ge 0) { Info ('/data 可用 = ' + $free + ' KB') }
        Step '待推入的产物'
        if (Test-Path -LiteralPath $DbFile) {
            Info ($DbFile)
            Info ('  ' + (Get-Item -LiteralPath $DbFile).Length + ' 字节  sha256=' + (Sha256 $DbFile))
        } else { Warn ('还没有产物：' + $DbFile + '（先跑 build.ps1，或用 -Action RoundTrip）') }
        Info 'Status 完成：未对手机做任何写入。'
    }

    'Backup' {
        Assert-Adb
        $null = Get-Device
        $script:RootMode = Get-RootMode
        if ($script:RootMode -eq 'none') { Fail '设备上没有 root。' }
        $null = Get-WxInfo
        $dir = Invoke-Backup
        Info ('备份完成：' + $dir)
        Info '本次只读取手机，未做任何写入。'
    }

    'Push' {
        Assert-Adb
        $null = Get-Device
        $script:RootMode = Get-RootMode
        if ($script:RootMode -eq 'none') { Fail '设备上没有 root。' }
        $null = Get-WxInfo
        Step '推入前先备份'
        $dir = Invoke-Backup
        Step '推入'
        $ok = Push-Db $DbFile $dir '默认/指定产物'
        if ($ok -and -not $DryRun) { Watch-Logcat $dir }
    }

    { $_ -eq 'RoundTrip' -or $_ -eq 'Auto' } {
        Assert-Adb
        $null = Get-Device
        $script:RootMode = Get-RootMode
        if ($script:RootMode -eq 'none') { Fail '设备上没有 root。' }
        $null = Get-WxInfo
        Step '拉取手机当前库（含 WAL 合并）'
        $dir = Invoke-Backup
        $dbLocal = Join-Path $dir 'EnMicroMsg.db'
        $mergedLocal = Join-Path $dir 'EnMicroMsg.db+wal 合并.db'
        $k = Get-KeyFromPhone $dir $dbLocal

        Step '解密手机当前库（作为合并起点）'
        # 合并过 WAL 的版本更接近手机真实状态，但现实里 -wal 可能是上一代遗留（合并后解密不出来）。
        # 所以先试合并版：解密 + integrity_check 通过才采用，否则自动退回未合并的主库并告警。
        $basePlain = Join-Path $dir 'phone_plain.db'
        $baseSrc = $dbLocal
        $useMerged = $false
        if ((Test-Path -LiteralPath $mergedLocal) -and ((Md5 $mergedLocal) -ne (Md5 $dbLocal))) {
            $probePlain = Join-Path $dir 'phone_plain_merged.db'
            $null = Invoke-Native $PythonExe @($Decryptor, $mergedLocal, '--key', $k, '-o', $probePlain, '--quiet')
            $pic = ''
            if (Test-Path -LiteralPath $probePlain) { $pic = Get-FirstLine (Invoke-Native $SqliteExe @($probePlain, 'PRAGMA integrity_check;')) }
            if ($pic -eq 'ok') {
                $baseSrc = $mergedLocal
                Move-Item -LiteralPath $probePlain -Destination $basePlain -Force
                $useMerged = $true
                Info '起点用"已合并 WAL"的库（解密 + integrity_check 通过）'
            } else {
                Warn ('WAL 合并版解密后 integrity_check = ' + $pic + ' —— 该 -wal 很可能是上一代遗留，已自动退回未合并的主库')
                if (Test-Path -LiteralPath $probePlain) { Remove-Item -LiteralPath $probePlain -Force }
            }
        }
        if (-not $useMerged) { Info ('起点用拉取到的主库（未合并 WAL）：' + $dbLocal) }
        if (-not (Test-Path -LiteralPath $basePlain)) {
            $null = Invoke-Native $PythonExe @($Decryptor, $baseSrc, '--key', $k, '-o', $basePlain, '--quiet')
        }
        if (-not (Test-Path -LiteralPath $basePlain)) { Fail '解密手机库失败' }
        $ic = Get-FirstLine (Invoke-Native $SqliteExe @($basePlain, 'PRAGMA integrity_check;'))
        if ($ic -ne 'ok') { Fail ('解密出来的手机库 integrity_check = ' + $ic + '，中止（不要用坏起点去推）') }
        Info ('起点明文库 OK：表=' + (Get-FirstLine (Invoke-Native $SqliteExe @($basePlain, "SELECT count(*) FROM sqlite_master WHERE type='table';"))) + '  message=' + (Get-FirstLine (Invoke-Native $SqliteExe @($basePlain, 'SELECT count(*) FROM message;'))))

        Step '确定数据来源（-SourceDb auto 时自动查找并解密，默认）'
        $srcPlain = Resolve-SourcePlain
        Step '调用 build.ps1 合并数据并加密'
        $rtOut = Join-Path $dir 'roundtrip'
        $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Processor, '-BaseDb', $basePlain, '-SourceDb', $srcPlain, '-OutDir', $rtOut, '-Key', $k, '-KeyCheckDb', $dbLocal)
        $o = Invoke-Native 'powershell' $psArgs
        foreach ($l in ($o | Select-Object -Last 16)) { Info $l }
        $produced = Join-Path $rtOut 'EnMicroMsg.db'
        if (-not (Test-Path -LiteralPath $produced)) { Fail ('build.ps1 没产出加密库：' + $produced + '（原因见上面日志）') }
        Step '推入手机'
        $ok = Push-Db $produced $dir 'RoundTrip 产物'
        if ($ok -and -not $DryRun) { Watch-Logcat $dir }
    }

    'Rollback' {
        Assert-Adb
        $null = Get-Device
        $script:RootMode = Get-RootMode
        if ($script:RootMode -eq 'none') { Fail '设备上没有 root。' }
        $null = Get-WxInfo
        if (-not $BackupDir) {
            if (-not (Test-Path -LiteralPath $BackupRoot)) { Fail ('没有备份目录：' + $BackupRoot) }
            $all = @(Get-ChildItem -LiteralPath $BackupRoot -Directory | Sort-Object Name -Descending)
            foreach ($d in $all) {
                if (Test-Path -LiteralPath (Join-Path $d.FullName 'EnMicroMsg.db')) { $BackupDir = $d.FullName; break }
            }
            if (-not $BackupDir) { Fail '备份目录里没有可回滚的 EnMicroMsg.db' }
        }
        $db = Join-Path $BackupDir 'EnMicroMsg.db'
        if (-not (Test-Path -LiteralPath $db)) { Fail ('备份里没有主库：' + $db) }
        Step '回滚'
        Info ('将把 ' + $db + ' 推回 ' + $script:WxDb)
        $ok = Push-Db $db $BackupDir '回滚用备份' -SkipVersionCheck
        if ($ok -and -not $DryRun) { Watch-Logcat $BackupDir }
    }
}

if (-not $KeepTemp) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host ''
Write-Host '完成。'

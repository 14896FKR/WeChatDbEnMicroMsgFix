<#
.SYNOPSIS
    微信 EnMicroMsg.db 处理脚本：把高版本（如 8.0.78）的聊天数据合并进低版本（如 8.0.48）
    自己的明文库，再按微信的加密格式逐页加密成可直接推回手机的库，并做端到端自验。

.DESCRIPTION
    流程：预检 → 复制到 TEMP 工作区 → 校验输入 → 确定密钥 → 生成并执行合并脚本 →
          合并后自检 → 逐页加密 → 往返逐字节自验 → 落盘（旧产物自动挪进 _旧_<时间戳>）→ 清理 TEMP

    安全约定（改动本脚本时务必保留）：
      · 全程不执行 PRAGMA journal_mode：起点库本身就是 wal，保持文件头 WAL 标志 2,2 即可。
      · 不动 TablesVersion：保留低版本自己的版本账本（高版本的会带进"未来版本"标记）。
      · 不搬钱包/支付、账号状态、统计缓存类表，降低旧版被新版状态卡住的概率。

    注意：加密使用全新随机 salt + 每页随机 IV，因此每次运行产出的加密库 SHA256 都会不同
    （数据等价，字节不同）。要判断两份加密库是否等价，请各自解回明文后比对内容区。

.PARAMETER BaseDb
    起点：低版本（手机自己在用）的明文库。
    默认 data\base-plain.db
.PARAMETER SourceDb
    数据来源：高版本明文库。默认 data\source-plain.db
.PARAMETER OutDir
    输出目录。默认 <脚本目录>\输出
.PARAMETER Key
    7 位十六进制密钥。不填则从 -KeyXml 里的 uin 反推候选并自动逐一验证。
.PARAMETER KeyXml
    auth_info_key_prefs.xml 路径（密钥反推用）。默认 <脚本目录>\auth_info_key_prefs.xml
.PARAMETER Imei
    参与 MD5(IMEI+uin) 的 IMEI。默认 1234567890ABCDEF（微信常见默认值）。
.PARAMETER KeyCheckDb
    用于判定密钥是否正确的加密原件（只读：解密 + integrity_check 验证其可用）。
    默认自动取较小的那份加密库（文件小、验证快）。
.PARAMETER ExtraExclude
    在默认排除清单之外再排除的表名。
.PARAMETER PythonExe
    Python 解释器（需装 cryptography）。默认 python
.PARAMETER SqliteExe
    3.x sqlite3.exe。默认 tools\sqlite3.exe
.PARAMETER Encryptor
    加密器脚本。默认 <OutDir>\wechat_encrypt.py，回退 <脚本目录>\tools\wechat_encrypt.py
.PARAMETER Decryptor
    解密器脚本。默认 tools\wechat_decrypt.py
.PARAMETER KeepTemp
    保留 TEMP 工作目录（排查问题用）。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1

.EXAMPLE
    .\build.ps1 -Key 504abcd -OutDir .\输出 -KeepTemp
    
#>
[CmdletBinding()]
param(
    [string]$BaseDb,
    [string]$Config,
    [string]$SourceDb,
    [string]$OutDir,
    [string]$Key,
    [string]$KeyXml,
    [string]$Imei = '1234567890ABCDEF',
    [string]$KeyCheckDb,
    [string[]]$ExtraExclude = @(),
    [string]$PythonExe = 'python',
    [string]$SqliteExe,
    [string]$Encryptor,
    [string]$Decryptor,
    [switch]$KeepTemp
)

$ErrorActionPreference = 'Stop'
$env:PYTHONIOENCODING = 'utf-8'
$script:StepNo = 0

function Step([string]$m) { $script:StepNo++; Write-Host ('[{0}] {1}' -f $script:StepNo, $m) }
function Info([string]$m) { Write-Host ('    ' + $m) }
function Warn([string]$m) { Write-Host ('    [警告] ' + $m) -ForegroundColor Yellow }
function Fail([string]$m) { Write-Host ('[失败] ' + $m) -ForegroundColor Red; exit 1 }
function MaskKey([string]$k) { if (-not $k) { return '(未设置)' }; return $k.Substring(0, 3) + ('*' * [Math]::Max(1, $k.Length - 3)) }
function Fwd([string]$p) { return $p.Replace('\', '/') }
# PS 5.1 的 Get-Content 默认按系统 ANSI 读文件：无 BOM 的 UTF-8（含中文/JSON）会乱码甚至解析失败。
# 统一用显式 UTF-8 读（带 BOM 的也能正确识别并剥掉）—— .json 按 R13 必须无 BOM，所以必须走显式编码。
function Read-TextFile([string]$p) { return [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8) }

# 调用外部程序：吞掉 stderr 的 ErrorRecord，避免 $ErrorActionPreference='Stop' 下被当成终止错误
# （用错密钥试解、或拿 sqlite3 读加密库时，报错走 stderr 属正常流程）
function Invoke-Native([string]$exe, [string[]]$argv) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $o = & $exe @argv 2>&1 } finally { $ErrorActionPreference = $prev }
    $res = @()
    foreach ($x in @($o)) {
        if ($x -is [System.Management.Automation.ErrorRecord]) { $res += $x.ToString() } else { $res += [string]$x }
    }
    return $res
}

# 只允许对 TEMP 工作副本做数据库操作（安全闸门）
function Assert-Work([string]$p) {
    if (-not $p.StartsWith($script:Work, [StringComparison]::OrdinalIgnoreCase)) {
        Fail "安全拦截：试图对工作区之外的文件执行数据库操作：$p"
    }
}
function Invoke-Sqlite([string]$db, [string]$sql) {
    Assert-Work $db
    return Invoke-Native $script:SqliteExe @($db, $sql)
}
function Invoke-SqliteFile([string]$db, [string]$sqlFile) {
    Assert-Work $db
    return Invoke-Native $script:SqliteExe @($db, ('.read ' + (Fwd $sqlFile)))
}
function Get-Header([string]$p) {
    $fs = [System.IO.File]::OpenRead($p)
    $b = New-Object byte[] 32
    $null = $fs.Read($b, 0, 32)
    $fs.Close()
    return $b
}
function Get-FirstLine([object]$o) {
    $a = @($o)
    if ($a.Count -eq 0) { return '' }
    return ([string]$a[0]).Trim()
}

# 默认排除清单：不搬这些表（低版本自带状态必须保留 / 高版本状态搬进去有风险）
$DefaultExclude = @(
    'TablesVersion',                 # 版本账本：必须保留低版本自己的
    'userinfo', 'userinfo2',         # 账号与设备状态
    'WalletBankcard', 'WalletUserInfo', 'WalletLuckyMoney', 'LuckyMoneyDetailOpenRecord',
    'LuckyMoneyEnvelopeResource', 'AAPayRecord', 'RemittanceRecord', 'AARecord', 'OfflineOrderStatus',
    'ABTestItem', 'netstat', 'oplog2', 'ActiveInfo', 'KindaCacheTable', 'walletcache', 'WepkgVersion',
    'IPCallPopularCountry', 'NewTipsInfo', 'NewTipsInfo2',
    'SmileyInfo', 'SmileyPanelConfigInfo', 'EmojiGroupInfo', 'EmojiDesignerProduct',
    'EmojiSuggestCacheInfo', 'GetEmotionListCache',
    'ChatroomNoticeAttachIndex'      # 高版本独有、低版本没有该表
)

# ---------- 配置文件（优先级：命令行 > 环境变量 > 配置文件 > 内置默认）----------
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
    'AdbExe', 'ProjectRoot', 'DbFile', 'SourceDb', 'SourceDir', 'SourceName', 'SourceRecurse',
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
$envMap = [ordered]@{ PythonExe = 'WECHATDBFIX_PYTHON'; SqliteExe = 'WECHATDBFIX_SQLITE'; Decryptor = 'WECHATDBFIX_DECRYPTOR'; Encryptor = 'WECHATDBFIX_ENCRYPTOR'; KeyXml = 'WECHATDBFIX_KEY_XML'; Key = 'WECHATDBFIX_KEY'; Imei = 'WECHATDBFIX_IMEI'; BaseDb = 'WECHATDBFIX_BASE_DB'; SourceDb = 'WECHATDBFIX_SOURCE_DB'; OutDir = 'WECHATDBFIX_OUT_DIR' }
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
# ---------- 路径解析 ----------
$root = $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $root) { $root = (Get-Location).Path }
if (-not $BaseDb)    { $BaseDb    = Join-Path $root 'data\base-plain.db' }
if (-not $SourceDb)  { $SourceDb  = Join-Path $root 'data\source-plain.db' }
if (-not $OutDir)    { $OutDir    = Join-Path $root 'output' }
if (-not $KeyXml)    { $KeyXml    = Join-Path $root 'auth_info_key_prefs.xml' }
if (-not $SqliteExe) { $SqliteExe = Join-Path $root 'tools\sqlite3.exe' }
if (-not $Decryptor) { $Decryptor = Join-Path $root 'tools\wechat_decrypt.py' }
if (-not $Encryptor) {
    $encCand = @(@((Join-Path $OutDir 'wechat_encrypt.py'), (Join-Path $root 'tools\wechat_encrypt.py')) | Where-Object { Test-Path -LiteralPath $_ })
    if ($encCand.Count -gt 0) { $Encryptor = [string]$encCand[0] } else { $Encryptor = Join-Path $root 'tools\wechat_encrypt.py' }
}
$script:SqliteExe = $SqliteExe
# 配置/环境变量里给的相对路径（例如 .venv/Scripts/python.exe）：按包目录解析成绝对路径，
# 裸命令名（如 python）仍交给 PATH 查找。
foreach ($vn in @('PythonExe', 'SqliteExe', 'Decryptor', 'Encryptor', 'Processor')) {
    $vv = [string](Get-Variable -Name $vn -ValueOnly)
    if (-not $vv) { continue }
    if ($vn -eq 'PythonExe' -and $vv -notmatch '[\\/]') { continue }
    if (-not [System.IO.Path]::IsPathRooted($vv)) {
        $rc = Join-Path $root $vv
        if (Test-Path -LiteralPath $rc) { Set-Variable -Name $vn -Value $rc -Scope Script }
    }
}


Write-Host '==== 微信 EnMicroMsg.db 处理脚本 ===='

# ---------- 1. 预检 ----------
Step '预检'
Info "脚本目录 = $root"
Info "sqlite3  = $SqliteExe"
Info "解密器   = $Decryptor"
Info "加密器   = $Encryptor"
$deps = @(
    [pscustomobject]@{ 名称 = '起点库';  路径 = $BaseDb },
    [pscustomobject]@{ 名称 = '来源库';  路径 = $SourceDb },
    [pscustomobject]@{ 名称 = 'sqlite3'; 路径 = $SqliteExe },
    [pscustomobject]@{ 名称 = '解密器';  路径 = $Decryptor },
    [pscustomobject]@{ 名称 = '加密器';  路径 = $Encryptor }
)
foreach ($d in $deps) {
    if ([string]::IsNullOrWhiteSpace($d.路径)) { Fail ($d.名称 + ' 的路径为空（参数没给对？）') }
    if (-not (Test-Path -LiteralPath $d.路径)) { Fail ('找不到' + $d.名称 + '：' + $d.路径) }
}
$pyVer = Get-FirstLine (Invoke-Native $PythonExe @('-c', 'import sys; print(sys.version.split()[0])'))
if ($LASTEXITCODE -ne 0) { Fail "调用 python 失败（$PythonExe）：$pyVer" }
$null = Invoke-Native $PythonExe @('-c', 'import cryptography')
if ($LASTEXITCODE -ne 0) { Fail "python 缺少 cryptography，请先 pip install cryptography（解释器 $PythonExe）" }
Info "python $pyVer / cryptography OK"
Info ('sqlite3 = ' + (Get-FirstLine (Invoke-Native $SqliteExe @('-version'))))
Info "起点库  = $BaseDb"
Info "来源库  = $SourceDb"

# ---------- 2. TEMP 工作副本 ----------
Step '复制到 TEMP 工作区（项目内文件只读，绝不就地操作）'
$script:Work = Join-Path $env:TEMP ('wxmerge-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $script:Work | Out-Null
$work = $script:Work
$base = Join-Path $work 'base.db'
$src  = Join-Path $work 'src.db'
Copy-Item -LiteralPath $BaseDb   -Destination $base -Force
Copy-Item -LiteralPath $SourceDb -Destination $src  -Force
Info "工作目录 = $work"

# ---------- 3. 校验输入 ----------
Step '校验输入库'
function Assert-PlainSqlite([string]$p, [string]$label) {
    $b = Get-Header $p
    $len = (Get-Item -LiteralPath $p).Length
    $magic = -join ($b[0..15] | ForEach-Object { [char]$_ })
    if ($magic -ne 'SQLite format 3') { Fail "$label 不是明文 SQLite 库（可能还是加密的，请先用 wechat_decrypt.py 解密）：$p" }
    if ($len % 1024 -ne 0) { Fail "$label 大小不是 1024 的整数倍：$len" }
    $psz = [int]$b[16] * 256 + [int]$b[17]
    if ($psz -ne 1024) { Fail "$label page_size = $psz，微信库应为 1024" }
    if ($b[18] -ne 2 -or $b[19] -ne 2) { Fail "$label 文件头 WAL 标志是 $($b[18]),$($b[19])，微信库应为 2,2（wal）" }
    if ($b[20] -ne 16) { Fail "$label reserve 字节是 $($b[20])，微信无 HMAC 布局应为 16" }
    Info ("{0}：{1} 字节 / page_size={2} / WAL={3},{4} / reserve={5}" -f $label, $len, $psz, $b[18], $b[19], $b[20])
}
Assert-PlainSqlite $base '起点库'
Assert-PlainSqlite $src  '来源库'
$baseTables = [int](Get-FirstLine (Invoke-Sqlite $base "SELECT count(*) FROM sqlite_master WHERE type='table';"))
$baseIndex  = [int](Get-FirstLine (Invoke-Sqlite $base "SELECT count(*) FROM sqlite_master WHERE type='index';"))
$baseTV     = [int](Get-FirstLine (Invoke-Sqlite $base 'SELECT count(*) FROM TablesVersion;'))
Info "起点库：表 $baseTables / 索引 $baseIndex / TablesVersion $baseTV 行"

# ---------- 4. 确定密钥 ----------
Step '确定密钥'
$keySrc = '命令行 -Key（未验证）'
if (-not $Key) {
    if (-not (Test-Path -LiteralPath $KeyXml)) { Fail "未提供 -Key，且找不到 -KeyXml：$KeyXml" }
    if (-not $KeyCheckDb) {
        $candDb = @(@((Join-Path $root 'data\8048TmpDb\EnMicroMsg.db'), (Join-Path $root 'data\8078TmpDb\EnMicroMsg.db')) | Where-Object { Test-Path -LiteralPath $_ })
        if ($candDb.Count -eq 0) { Fail '未提供 -Key，也找不到可用于验证密钥的加密原件（请用 -KeyCheckDb 指定）' }
        $sortedCand = @($candDb | Sort-Object { (Get-Item -LiteralPath $_).Length })
        $KeyCheckDb = [string]$sortedCand[0]
    }
    $xml = Read-TextFile $KeyXml
    $uins = @([regex]::Matches($xml, '\d{8,12}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    if ($uins.Count -eq 0) { Fail "在 $KeyXml 里找不到形如 uin 的数字" }
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $candKeys = @()
    foreach ($u in $uins) {
        $h = ($md5.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Imei + $u)) | ForEach-Object { $_.ToString('x2') }) -join ''
        $candKeys += $h.Substring(0, 7)
    }
    $md5.Dispose()
    $candKeys = @($candKeys | Select-Object -Unique)
    Info ("从 {0} 反推 {1} 个候选密钥，用 {2} 逐个验证（解出 integrity_check=ok 且表数>100 才算通过）…" -f (Split-Path $KeyXml -Leaf), $candKeys.Count, (Split-Path $KeyCheckDb -Leaf))
    $probe = Join-Path $work 'keyprobe.db'
    foreach ($c in $candKeys) {
        if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Force }
        $null = Invoke-Native $PythonExe @($Decryptor, $KeyCheckDb, '--key', $c, '-o', $probe, '--quiet')
        if (-not (Test-Path -LiteralPath $probe)) { continue }
        $ic = Get-FirstLine (Invoke-Sqlite $probe 'PRAGMA integrity_check;')
        $tc = Get-FirstLine (Invoke-Sqlite $probe "SELECT count(*) FROM sqlite_master WHERE type='table';")
        $okCount = $false
        if ($tc -match '^\d+$') { if ([int]$tc -gt 100) { $okCount = $true } }
        if ($ic -eq 'ok' -and $okCount) { $Key = $c; break }
    }
    if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Force }
    if (-not $Key) { Fail "所有候选密钥都解不开验证库（$KeyCheckDb）。请用 -Key 手工指定正确密钥。" }
    $keySrc = ('由 {0} 反推，并用 {1} 验证通过' -f (Split-Path $KeyXml -Leaf), (Split-Path $KeyCheckDb -Leaf))
}
Info ("密钥 = {0}　（{1}）" -f (MaskKey $Key), $keySrc)

# ---------- 5. 生成并执行合并脚本 ----------
Step '生成合并脚本'
$exclude = @($DefaultExclude + $ExtraExclude)
$sharedSql = Join-Path $work 'shared.sql'
$q = "ATTACH DATABASE '" + (Fwd $src) + "' AS src;`n"
$q += "SELECT name FROM main.sqlite_master WHERE type='table' AND name IN (SELECT name FROM src.sqlite_master WHERE type='table') ORDER BY name;`n"
[System.IO.File]::WriteAllText($sharedSql, $q, (New-Object System.Text.UTF8Encoding $false))
$shared = @(Invoke-SqliteFile $base $sharedSql | Where-Object { $_ -ne '' })
if ($shared.Count -eq 0) { Fail '两库没有同名表，输入可能搞反了' }

$infoSql = Join-Path $work 'info.sql'
$q = "ATTACH DATABASE '" + (Fwd $src) + "' AS src;`n"
foreach ($t in $shared) {
    $q += "SELECT '$t'||'|'||(SELECT count(*) FROM pragma_index_list('$t') WHERE [unique]=1)||'|'||(SELECT count(*) FROM pragma_table_info('$t') WHERE pk>0)||'|'||(SELECT count(*) FROM main.[$t])||'|'||(SELECT count(*) FROM src.[$t]);`n"
}
[System.IO.File]::WriteAllText($infoSql, $q, (New-Object System.Text.UTF8Encoding $false))
$info = @{}
foreach ($l in (Invoke-SqliteFile $base $infoSql)) {
    if ($l -notmatch '\|') { continue }
    $p = @($l.Split('|'))
    if ($p.Count -lt 5) { continue }
    $info[$p[0]] = [pscustomobject]@{ uniq = [int]$p[1]; pk = [int]$p[2]; before = [int]$p[3]; src = [int]$p[4] }
}

# 取列名：两个库各查一遍。
# 注意不要用 pragma_table_info('src.[表]') 这种 schema 限定写法 —— 并非所有 SQLite 版本都成立，
# 取不到列就会把整张表算成"没有同名列"从而漏搬。
$colBaseSql = Join-Path $work 'cols_base.sql'
$colSrcSql = Join-Path $work 'cols_src.sql'
$qb = ''; $qs = ''
foreach ($t in $shared) {
    $one = "SELECT '$t'||'|'||(SELECT group_concat(name) FROM (SELECT name FROM pragma_table_info('$t') ORDER BY cid));`n"
    $qb += $one
    $qs += $one
}
[System.IO.File]::WriteAllText($colBaseSql, $qb, (New-Object System.Text.UTF8Encoding $false))
[System.IO.File]::WriteAllText($colSrcSql, $qs, (New-Object System.Text.UTF8Encoding $false))
$bcolsOf = @{}
foreach ($l in (Invoke-SqliteFile $base $colBaseSql)) {
    if ($l -notmatch '\|') { continue }
    $p = @($l.Split('|'))
    if ($p.Count -lt 2 -or $p[1] -eq '') { continue }
    $bcolsOf[$p[0]] = @($p[1] -split ',')
}
$scolsOf = @{}
foreach ($l in (Invoke-SqliteFile $src $colSrcSql)) {
    if ($l -notmatch '\|') { continue }
    $p = @($l.Split('|'))
    if ($p.Count -lt 2 -or $p[1] -eq '') { continue }
    $scolsOf[$p[0]] = @($p[1] -split ',')
}

$copy = @()
$emptyInSource = 0
$noCols = @()
foreach ($t in $shared) {
    if (-not $info.ContainsKey($t)) { continue }
    if ($info[$t].src -le 0) { $emptyInSource++; continue }
    if ($exclude -contains $t) { continue }
    if (-not $bcolsOf.ContainsKey($t) -or -not $scolsOf.ContainsKey($t)) { $noCols += $t; continue }
    $common = @($bcolsOf[$t] | Where-Object { $scolsOf[$t] -contains $_ })
    if ($common.Count -eq 0) { $noCols += $t; continue }
    $copy += $t
}
if ($noCols.Count -gt 0) { Warn ('取不到列名或没有同名列、跳过：' + ($noCols -join '、')) }
if ($copy.Count -eq 0) { Fail '没有需要搬的表（来源库全为空，或列名取不到？）' }
$noKey = @($copy | Where-Object { $info[$_].uniq -eq 0 -and $info[$_].pk -eq 0 })
$excludedHere = $shared.Count - $emptyInSource - $copy.Count
Info ("共有表 {0} 张；来源库有数据的 {1} 张；本次搬入 {2} 张；排除/跳过 {3} 张" -f $shared.Count, ($shared.Count - $emptyInSource), $copy.Count, $excludedHere)
if ($noKey.Count -gt 0) { Info ('无主键/唯一索引、改用 DELETE+INSERT 的 ' + $noKey.Count + ' 张：' + ($noKey -join '、')) }

# 按【列名交集】搬，不用 SELECT *：起点库常常比来源库少几列（版本代差），
# 直接 SELECT * 会因"列数不符"整表失败。
$mergeSql = Join-Path $work 'merge.sql'
$lines = @("ATTACH DATABASE '" + (Fwd $src) + "' AS old;", 'BEGIN IMMEDIATE;')
$dropNotes = @()
$extraBase = @()
foreach ($t in $copy) {
    $common = @($bcolsOf[$t] | Where-Object { $scolsOf[$t] -contains $_ })
    $dropped = @($scolsOf[$t] | Where-Object { $bcolsOf[$t] -notcontains $_ })
    $bonly = @($bcolsOf[$t] | Where-Object { $scolsOf[$t] -notcontains $_ })
    if ($dropped.Count -gt 0) { $dropNotes += ($t + ' 丢' + $dropped.Count + '列') }
    if ($bonly.Count -gt 0) { $extraBase += ($t + '（' + ($bonly -join '/') + '）') }
    $cols = (($common | ForEach-Object { '[' + $_ + ']' }) -join ',')
    if ($noKey -contains $t) { $lines += "DELETE FROM main.[$t]; INSERT INTO main.[$t] ($cols) SELECT $cols FROM old.[$t];" }
    else { $lines += "INSERT OR REPLACE INTO main.[$t] ($cols) SELECT $cols FROM old.[$t];" }
}
$lines += @('COMMIT;', 'DETACH DATABASE old;', 'PRAGMA wal_checkpoint(TRUNCATE);')
[System.IO.File]::WriteAllText($mergeSql, ($lines -join "`n") + "`n", (New-Object System.Text.UTF8Encoding $false))
if ($dropNotes.Count -gt 0) {
    Info ('列代差：' + $dropNotes.Count + ' 张表来源库有更多列，已按列名交集搬入（新列丢弃）')
    Info ('  ' + ($dropNotes -join '、'))
}
if ($extraBase.Count -gt 0) { Warn ('起点库有、来源库没有的列（这些列将留空）：' + ($extraBase -join '、')) }
Step ('执行合并（' + $copy.Count + ' 张表）')
# PRAGMA wal_checkpoint(TRUNCATE) 会回一行 "busy|log|checkpointed"，属正常输出，需排除
$mout = @(Invoke-SqliteFile $base $mergeSql | Where-Object { $_ -ne '' -and $_ -notmatch '^\d+\|\d+\|\d+$' })
if ($mout.Count -gt 0) { Fail ('合并脚本有输出（通常意味着报错）：' + ($mout -join ' / ')) }

# ---------- 6. 合并后自检 ----------
Step '合并后自检'
$hdr = Get-Header $base
if ($hdr[18] -ne 2 -or $hdr[19] -ne 2) { Fail "合并后 WAL 标志被改动：$($hdr[18]),$($hdr[19])" }
if ($hdr[20] -ne 16) { Fail "合并后 reserve 被改动：$($hdr[20])" }
if ([int]$hdr[16] * 256 + [int]$hdr[17] -ne 1024) { Fail '合并后 page_size 被改动' }
$ic = Get-FirstLine (Invoke-Sqlite $base 'PRAGMA integrity_check;')
if ($ic -ne 'ok') { Fail "integrity_check = $ic" }
$jm = Get-FirstLine (Invoke-Sqlite $base 'PRAGMA journal_mode;')
if ($jm -ne 'wal') { Fail "journal_mode = $jm（应为 wal）" }
$tbl = [int](Get-FirstLine (Invoke-Sqlite $base "SELECT count(*) FROM sqlite_master WHERE type='table';"))
$idx = [int](Get-FirstLine (Invoke-Sqlite $base "SELECT count(*) FROM sqlite_master WHERE type='index';"))
$tv  = [int](Get-FirstLine (Invoke-Sqlite $base 'SELECT count(*) FROM TablesVersion;'))
if ($tbl -ne $baseTables) { Fail "表数被改动：$baseTables -> $tbl" }
if ($idx -ne $baseIndex)  { Fail "索引数被改动：$baseIndex -> $idx" }
if ($tv  -ne $baseTV)     { Fail "TablesVersion 行数被改动：$baseTV -> $tv（必须保留低版本自己的）" }
$afterSql = Join-Path $work 'after.sql'
$q = "ATTACH DATABASE '" + (Fwd $src) + "' AS src;`n"
foreach ($t in $copy) { $q += "SELECT '$t'||'|'||(SELECT count(*) FROM main.[$t])||'|'||(SELECT count(*) FROM src.[$t]);`n" }
[System.IO.File]::WriteAllText($afterSql, $q, (New-Object System.Text.UTF8Encoding $false))
$report = @()
$less = @(); $extra = @()
foreach ($l in (Invoke-SqliteFile $base $afterSql)) {
    if ($l -notmatch '\|') { continue }
    $p = @($l.Split('|'))
    if ($p.Count -lt 3) { continue }
    $n = $p[0]; $a = [int]$p[1]; $s = [int]$p[2]
    $report += [pscustomobject]@{ Table = $n; BaseBefore = $info[$n].before; Source = $s; After = $a }
    if ($a -lt $s) { $less += "$n($a<$s)" }
    if ($a -gt $s) { $extra += "$n(+$($a-$s))" }
}
if ($less.Count -gt 0) { Fail ('有表行数少于来源库，数据丢失：' + ($less -join '、')) }
$msgRow = Get-FirstLine (Invoke-Sqlite $base 'SELECT count(*) FROM message;')
$talkerRow = Get-FirstLine (Invoke-Sqlite $base 'SELECT count(DISTINCT talker) FROM message;')
Info ("表 {0} / 索引 {1} / TablesVersion {2} 行（与合并前一致）；journal_mode=wal，integrity_check=ok" -f $tbl, $idx, $tv)
Info ("message = $msgRow 行 / 会话 $talkerRow 个")
if ($extra.Count -gt 0) { Info ('保留低版本自带基线行的表：' + ($extra -join '、')) }

# ---------- 7. 逐页加密 ----------
Step '逐页加密（AES-256-CBC / page 1024 / kdf_iter 4000 / 无 HMAC）'
$encOut = Join-Path $work 'EnMicroMsg.db'
$eo = @(Invoke-Native $PythonExe @($Encryptor, 'encrypt', $base, $encOut, $Key))
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $encOut)) { Fail ('加密失败：' + ($eo -join ' / ')) }
foreach ($l in $eo) { Info $l }
$encLen = (Get-Item -LiteralPath $encOut).Length
$plainLen = (Get-Item -LiteralPath $base).Length
if ($encLen -ne $plainLen) { Fail "加密后大小变化：$plainLen -> $encLen" }
$eh = Get-Header $encOut
if ((-join ($eh[0..15] | ForEach-Object { [char]$_ })) -eq 'SQLite format 3') { Fail '加密库头部仍是明文 SQLite 头，加密没生效' }

# ---------- 8. 往返自验 ----------
Step '往返自验（用项目自带解密器解回来逐字节比对内容区）'
$rt = Join-Path $work 'roundtrip.db'
$null = Invoke-Native $PythonExe @($Decryptor, $encOut, '--key', $Key, '-o', $rt, '--quiet')
if (-not (Test-Path -LiteralPath $rt)) { Fail '解回失败：解密器没有输出' }
$cmpPy = Join-Path $work 'cmp.py'
$cmpSrc = @'
import sys
PAGE = 1024
RES = 16
a = open(sys.argv[1], 'rb').read()
b = open(sys.argv[2], 'rb').read()
if len(a) != len(b):
    print('SIZE %d %d' % (len(a), len(b)))
    raise SystemExit(1)
diff = 0
pages = 0
for p in range(len(a) // PAGE):
    s = p * PAGE
    e = s + PAGE - RES
    if a[s:e] != b[s:e]:
        pages += 1
        diff += sum(1 for i in range(s, e) if a[i] != b[i])
print('%d %d' % (diff, pages))
'@
[System.IO.File]::WriteAllText($cmpPy, $cmpSrc, (New-Object System.Text.UTF8Encoding $false))
$cmp = Get-FirstLine (Invoke-Native $PythonExe @($cmpPy, $base, $rt))
$parts = @($cmp -split '\s+')
if ($parts.Count -lt 2) { Fail "往返比对输出异常：$cmp" }
if ([int]$parts[0] -ne 0) { Fail "往返比对失败（差异 $($parts[0]) 字节 / $($parts[1]) 页），产物不可信" }
$ric = Get-FirstLine (Invoke-Sqlite $rt 'PRAGMA integrity_check;')
$rtMsg = Get-FirstLine (Invoke-Sqlite $rt 'SELECT count(*) FROM message;')
$rhdr = Get-Header $rt
if ($ric -ne 'ok') { Fail "解回后 integrity_check = $ric" }
if ($rhdr[18] -ne 2 -or $rhdr[19] -ne 2 -or $rhdr[20] -ne 16) { Fail '解回后 WAL 标志 / reserve 不正确' }
if ([int]$rhdr[16] * 256 + [int]$rhdr[17] -ne 1024) { Fail '解回后 page_size 不正确' }
Info "内容区差异 = 0 字节；解回后 integrity_check = ok，message = $rtMsg 行，WAL 标志 2,2 / reserve 16 / page_size 1024"

# ---------- 9. 落盘 ----------
Step '落盘'
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$oldDir = Join-Path $OutDir ('_旧_' + $stamp)
foreach ($n in @('EnMicroMsg.db', 'EnMicroMsg.plaintext.db', 'merge.sql', '处理报告.txt')) {
    $p = Join-Path $OutDir $n
    if (Test-Path -LiteralPath $p) {
        if (-not (Test-Path -LiteralPath $oldDir)) { New-Item -ItemType Directory -Force -Path $oldDir | Out-Null }
        Move-Item -LiteralPath $p -Destination (Join-Path $oldDir $n) -Force
    }
}
Copy-Item -LiteralPath $encOut   -Destination (Join-Path $OutDir 'EnMicroMsg.db') -Force
Copy-Item -LiteralPath $base     -Destination (Join-Path $OutDir 'EnMicroMsg.plaintext.db') -Force
Copy-Item -LiteralPath $mergeSql -Destination (Join-Path $OutDir 'merge.sql') -Force
if (Test-Path -LiteralPath $oldDir) { Info "旧产物已挪到：$oldDir" }

$hEnc = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $OutDir 'EnMicroMsg.db')).Hash
$hPla = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $OutDir 'EnMicroMsg.plaintext.db')).Hash
$rep = @()
$rep += '微信 EnMicroMsg.db 处理报告'
$rep += ('时间：' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$rep += ('起点库：' + $BaseDb)
$rep += ('来源库：' + $SourceDb)
$rep += ('密钥：' + (MaskKey $Key) + '（' + $keySrc + '）')
$rep += ('搬入 ' + $copy.Count + ' 张表；排除 ' + $excludedHere + ' 张；来源库为空未搬 ' + $emptyInSource + ' 张')
$rep += ('搬入清单：' + ($copy -join '、'))
$rep += ''
$rep += ('EnMicroMsg.db            sha256 = ' + $hEnc + '  (' + $encLen + ' 字节)')
$rep += ('EnMicroMsg.plaintext.db  sha256 = ' + $hPla + '  (' + $plainLen + ' 字节)')
$rep += ''
$rep += '自验：往返内容区差异 0 字节 / integrity_check ok / journal_mode wal / page_size 1024 / reserve 16 / WAL 标志 2,2'
$rep += ('合并后：表 ' + $tbl + ' / 索引 ' + $idx + ' / TablesVersion ' + $tv + ' 行 / message ' + $msgRow + ' 行 / 会话 ' + $talkerRow + ' 个')
$rep += ''
$rep += '逐表行数（合并前 -> 来源 -> 合并后）：'
foreach ($r in ($report | Sort-Object Table)) {
    $rep += ('  {0,-34} {1,6} -> {2,6} -> {3,6}' -f $r.Table, $r.BaseBefore, $r.Source, $r.After)
}
[System.IO.File]::WriteAllText((Join-Path $OutDir '处理报告.txt'), (($rep -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding $true))

Info ("产物 EnMicroMsg.db ({0} 字节) sha256={1}" -f $encLen, $hEnc)
Info ("     EnMicroMsg.plaintext.db ({0} 字节) sha256={1}" -f $plainLen, $hPla)
Info '     merge.sql / 处理报告.txt'

# ---------- 10. 收尾 ----------
if ($KeepTemp) { Info "TEMP 工作目录已保留：$work" }
else {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    Info 'TEMP 工作目录已清理'
}
Write-Host ''
Write-Host '完成。手机侧仍未验证：接上数据线后请先 adb pull 备份手机现有 EnMicroMsg.db / -wal / -shm，再推入本产物。'

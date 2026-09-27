# WeChatDbEnMicroMsgFix — 微信 EnMicroMsg.db 降级迁移工具箱

把**高版本**微信库（如 8.0.78）里的聊天记录，搬进**手机正在使用的低版本**（如 8.0.48）数据库，
并保持微信的 SQLCipher 1 加密格式，让手机微信能正常打开、记录可见。

> 本仓库只包含脚本与必要工具，**不含任何聊天数据、密钥或备份**；所有路径按本目录解析，
> 可用**环境变量**或 `config.json` 覆盖，脚本里没有写死任何盘符或本机位置。

---

## 一、目录结构

| 路径 | 说明 |
|---|---|
| `setup.ps1` | **环境引导**（只跑一次）：探测解释器 → 建包内 `.venv`（或复用系统解释器）→ 装依赖 → 写 `config.json` → 跑 Selftest 验收 |
| `build.ps1` | **处理管线**：预检 → 临时区 → 定密钥 → 合并 → 自检 → 逐页加密 → 往返自验 → 落盘 |
| `push.ps1` | **手机端脚本**：`Selftest` / `Status` / `Backup` / `Push` / `RoundTrip` / `Auto` / `Rollback` |
| `tools/sqlite3.exe` | SQLite 官方 CLI（读写明文库）；随包 **3.53.4**，来源与更新方式见 `tools/CREDITS.txt` |
| `tools/adb.exe`（可选） | 你自行放置的 adb；脚本优先用它（**须与 `AdbWinApi.dll`、`AdbWinUsbApi.dll` 同目录**） |
| `tools/wechat_decrypt.py` | 上游开源解密器（微信库 → 明文） |
| `tools/wechat_encrypt.py` | 逐页加密器（明文 → 微信格式；与上面互为逆运算） |
| `tools/walmerge.py` | WAL 合并器（照 `sqlite wal.c` 恢复规则实现） |
| `data/` | **放数据源库**（高版本库，明文或加密都行）——空目录，需你自己放 |
| `output/` | 处理产物（加密库 / 明文库 / merge.sql / 处理报告.txt） |
| `phone-backups/` | 每次推手机前自动拉下来的三件套与 logcat（**回滚依赖，别删最近的**） |
| `config.example.json` | 配置模板：复制成 `config.json` 后按需修改 |
| `config.json` | 你的实际配置（`setup.ps1` 会写入 `PythonExe`）；**不入库** |
| `LICENSE` | MIT 许可；第三方来源与授权见 `tools/CREDITS.txt` |
| `.venv/` | `setup.ps1` 建的解释器环境（可随时删掉重建）；**不入库** |

---

## 二、前置条件

| 项 | 要求 | 说明 |
|---|---|---|
| 系统 | Windows 10/11 + PowerShell 5.1 或 7 | 脚本按 5.1 兼容写的；需**普通会话（FullLanguage）**——脚本会调用 .NET 基础类库（文件读写、MD5、编码），受限语言模式（企业锁定 / AppLocker / JEA）会把这些调用拦下 |
| Python | 3.7+（任意一个即可，**不必预先装库**） | 先跑一次 `setup.ps1`：它在包内建 `.venv` 并装好 `cryptography` + `pycryptodome`；没网络用 `-Offline`；也可用 `-PythonExe` / `WECHATDBFIX_PYTHON` / `config.json` 指定 |
| adb | 可选（只有手机动作需要） | **不随包**（属 Google Android SDK 受 SDK 条款约束，且不是单文件）。获取：https://developer.android.com/tools/releases/platform-tools 。查找顺序：`tools\adb.exe` → PATH → 常见安装位置；也可用 `-AdbExe` / `WECHATDBFIX_ADB` 指定 |
| 手机 | 已 root（Magisk 等）且已授权 | 需要读写 `/data/data/com.tencent.mm` |
| USB 模式 | **建议「不传输数据 / 仅充电」** | 部分机型在 MTP（文件传输）模式下会显示**未授权** |

---

## 三、快速开始（接线到结束）

```powershell
cd <本目录>

# ⓪ 环境引导（每台机器只跑一次）：准备 Python 环境 + 写入 config.json
.\setup.ps1

# ① 本地自检（不需要手机）：WAL 合并、加解密往返、数据源识别
.\push.ps1 -Action Selftest

# ② 看手机现状（只读）：版本 / 库路径 / 大小 / 权限 / SELinux 上下文 / 剩余空间
.\push.ps1 -Action Status

# ③ 全自动：自动找数据源 → 自动定密钥 → 备份 → 解密 → 合并 → 加密 → 自验 → 直接推送
.\push.ps1 -Action Auto
```

`-Action Auto` 中间**不需要任何参数**，它自己会：

1. 探测 adb / 设备 / root 方式（`su`、`su 0`、adb 已 root 三种）；
2. 找到手机微信库（**只认文件名 `EnMicroMsg.db`**；多个账号目录都有它时，取**修改时间最新**的那个并列出全部候选）；
3. **从手机拉 `auth_info_key_prefs.xml` 反推密钥**，并用 `integrity_check` 验证真伪；
4. **按文件名在 `data/` 等目录里找数据源**，加密的自动解密并校验；
5. 备份三件套 → 解密手机库 → 按列名交集合并 → 逐页加密 → 自验；
6. **推送**（force-stop 微信 → 设备内留 `.bak` → 删 `-wal/-shm` → `cp` 覆盖 → 恢复 SELinux 上下文与 owner/mode → md5 双向核对 → 抓 logcat）。

想先看产物再推：用 `-Action RoundTrip`（会问你要不要推，答 `no` 就只产出）。
出问题一键退回：`-Action Rollback`。

### 数据放哪

把高版本库（例如 `EnMicroMsg.db`）放进 `data/` 即可；脚本按**文件名**找

- 默认文件名：`EnMicroMsg.db`、`decrypted_EnMicroMsg.db`（先前者）
- 默认目录：`data/`、`data-src/`、本目录
- 同名多份取**修改时间最新**的那份，然后**逐个校验**（能解密 + `integrity_check=ok`），不过关就换下一个
- 要换位置或名字：改配置或用参数（见下）

**手机上的库怎么挑**：只认文件名 `EnMicroMsg.db`。若微信里登录过多个账号（`MicroMsg/` 下有多个 32 位目录），
脚本取**修改时间最新**的那个（正在用的账号），并把所有候选打印出来；要指定别的用 `-WxDb <完整路径>`。

---

## 四、配置：命令行 > 环境变量 > 配置文件 > 内置默认

### 4.1 配置文件

复制 `config.example.json` 为 `config.json`（同目录），只写要改的键；**空串或删掉该键 = 用内置默认**。

```json
{
  "SourceDir": ["data", "data-src", "."],
  "SourceName": ["EnMicroMsg.db", "decrypted_EnMicroMsg.db"],
  "ExpectVersion": "",
  "WaitSeconds": 25
}
```

- `SourceDir` 里的**相对路径按本目录解析**；
- `.json` **不要加 BOM**（严格解析器会报 `Unexpected UTF-8 BOM`）；
- 启动时会打印「已读取配置：…」和每个生效的键，便于核对；
- 想用别的配置文件：`-Config <路径>`。

### 4.2 环境变量

| 环境变量 | 对应参数 | 用途 |
|---|---|---|
| `WECHATDBFIX_ADB` | `-AdbExe` | adb.exe 路径 |
| `WECHATDBFIX_PYTHON` | `-PythonExe` | python 解释器（`setup.ps1` 也会把选中的解释器写进 `config.json`） |
| `WECHATDBFIX_SQLITE` | `-SqliteExe` | sqlite3 路径 |
| `WECHATDBFIX_KEY` / `WECHATDBFIX_IMEI` | `-Key` / `-Imei` | 密钥与 IMEI |
| `WECHATDBFIX_KEY_XML` | `-KeyXml` | 用于反推密钥的 `auth_info_key_prefs.xml` |
| `WECHATDBFIX_SOURCE_DB` | `-SourceDb` | 直接指定数据源文件（优先于目录搜索） |
| `WECHATDBFIX_SOURCE_DIR` | `-SourceDir` | 搜索目录，多个用 `;` 分隔 |
| `WECHATDBFIX_SOURCE_NAME` | `-SourceName` | 文件名，多个用 `;` 分隔 |
| `WECHATDBFIX_DB_FILE` | `-DbFile` | `Push` 要推入的加密库 |
| `WECHATDBFIX_WX_DB` | `-WxDb` | 手机上 `EnMicroMsg.db` 的完整路径（多个账号时指定用哪个） |
| `WECHATDBFIX_BACKUP_ROOT` | `-BackupRoot` | 备份根目录 |
| `WECHATDBFIX_EXPECT_VERSION` | `-ExpectVersion` | 目标手机版本守卫：**默认留空 = 不检查**；填了才校验，`8.0.48` 与 `8048` 两种写法等价 |
| `WECHATDBFIX_BASE_DB` / `WECHATDBFIX_OUT_DIR` | `-BaseDb` / `-OutDir` | 只在直接跑 `build.ps1` 时用 |
| `WECHATDBFIX_DECRYPTOR` / `_ENCRYPTOR` / `_PROCESSOR` | 同名参数 | 替换工具脚本位置 |

示例：

```powershell
$env:WECHATDBFIX_ADB = 'C:\platform-tools\adb.exe'
$env:WECHATDBFIX_SOURCE_DIR = 'D:\wechat-data;.\data'
.\push.ps1 -Action Auto
```

### 4.3 只看处理管线（不碰手机）

```powershell
.\build.ps1 -BaseDb .\data\base-plain.db -SourceDb .\data\source-plain.db -OutDir .\output -Key <7位密钥>
```

### 4.4 常用参数速查

| 脚本 | 参数 | 作用 |
|---|---|---|
| `setup.ps1` | `-Mode venv\|auto\|system` | venv（默认，建包内 `.venv`）/ auto（系统里有现成可用的就直接用）/ system（只用系统解释器） |
| | `-Offline` | 不联网：复用系统解释器已装好的库来建 `.venv` |
| | `-PipIndex` / `-PipProxy` / `-NoMirror` | 指定 pip 源 / 代理 / 关掉"失败自动换镜像重试" |
| | `-PythonExe` / `-Recreate` / `-NoSelftest` | 指定基础解释器 / 重建 `.venv` / 跳过收尾自检 |
| `push.ps1` | `-Action <动作>` | `Selftest` / `Status` / `Backup` / `Push` / `RoundTrip` / `Auto` / `Rollback` |
| | `-DryRun` / `-Yes` | 只打印计划 / 跳过人工确认（`Auto` 已隐含） |
| | `-SourceDb` / `-SourceDir` / `-SourceName` / `-SourceRecurse` | 数据源文件 / 搜索目录 / 文件名 / 递归查找 |
| | `-WxDb` / `-DbFile` / `-BackupRoot` / `-BackupDir` | 手机库路径 / 待推入的库 / 备份根目录 / 回滚到哪次备份 |
| | `-Key` / `-KeyXml` / `-Imei` | 手工密钥 / 反推密钥用的 xml / IMEI |
| | `-ExpectVersion` / `-AnyVersion` | 目标版本守卫（默认关） / 关掉守卫 |
| | `-NoStopApp` / `-WaitSeconds` / `-KeepTemp` | 备份时不 force-stop 微信 / 抓日志前等几秒 / 保留临时目录 |
| `build.ps1` | `-BaseDb` / `-SourceDb` / `-OutDir` / `-Key` | 起点明文库 / 来源明文库 / 输出目录 / 密钥 |
| | `-KeyXml` / `-KeyCheckDb` / `-Imei` | 反推密钥用 xml / 验证密钥用的加密原件 / IMEI |
| | `-ExtraExclude` / `-KeepTemp` | 追加排除表 / 保留临时目录 |

---

## 五、成功判据（缺一不算成功）

**构建阶段（脚本自动断言，任一条不满足即失败退出）**

| 判据 | 期望 |
|---|---|
| 起点/来源校验 | 明文 SQLite；大小是 1024 整数倍；`page_size=1024`；WAL 标志 `2,2`；reserve `16` |
| 合并后结构不变 | 表数 / 索引数 / `TablesVersion` 行数 **与合并前完全一致** |
| 合并后完整性 | `PRAGMA integrity_check` = `ok`；`journal_mode` = `wal` |
| 行数核对 | 每张搬入的表 **不少于**来源库（少于即判数据丢失，直接失败） |
| 往返自验 | 用加密库解回来的明文，与构建用的明文**内容区逐字节差异 = 0** |
| 加密后头部 | 不再是 `SQLite format 3`（证明真的加密了） |

**推送阶段**：三件套 `md5 一致 ✓`；设备内 `RESULT=OK` 且 **md5 双向一致 ✓**；logcat 无 `corrupt` / 损坏。

**事后独立核对（推荐）**：`-Action Backup` 拉回现库 → 解密 → 数 `message` 是否等于来源库条数。
注意：目标机自己新增的记录**不会被覆盖**（合并是 `INSERT OR REPLACE`，只增补来源库的行），
所以手机上的条数可能**比来源库多**，属正常。

---

## 六、红线与禁忌

1. **不要用 `tools/wechat_decrypt.py` 的「✓ 解密成功」当判据**：它无论密钥对错都会写出
   `SQLite format 3` 头并打印成功。**只有 `sqlite3 <库> "PRAGMA integrity_check"` = `ok` 才算解密成功。**
2. **不要推"起点不是目标手机当前库"的产物**：不同版本/不同机器生成的库，表结构与 `TablesVersion` 不同，
   推上去等于换 schema。
3. **不要把 `TablesVersion` 搬过去**：它是"每张表当前处于哪个 schema 版本"的账本，必须保留目标机自己的。
4. **不要执行 `PRAGMA journal_mode`**：起点库本来就是 wal，保持文件头 `2,2` 即可；
   旧版 SQLCipher 切模式会把库清成 1 KB。
5. **不要用 `SELECT *` 跨版本搬表**：低版本表常常少几列，列数不符会整表失败；要按**列名交集**逐列插入。
6. **不要把读写型第三方工具指向原始数据**（例如 SQLCipher CLI 直接开 `data/` 下的原件）：
   所有数据库操作只作用于临时区副本（脚本里有安全闸门，别绕过）。
7. **推手机前必须有完整备份**（脚本强制做），并且知道退路是 `-Action Rollback`。
8. **密钥 = `MD5(IMEI + uin)[:7]`**，uin 取自该手机的 `auth_info_key_prefs.xml`；换机/换账号都会变，
   每次都要用 `integrity_check` 现验。
9. `adb pull` **读不了 `/data/data`**（它是 shell 身份）：必须先用 root 复制到 `/data/local/tmp`
   并 `chmod 644`（必要时 `restorecon`）再拉（脚本已封装）。
10. **推之前确认插的是目标手机**：版本守卫**默认关闭**；需要防插错机时，在 `config.json` 或 `-ExpectVersion` 里
    写目标版本（`8.0.48` 与 `8048` 等价）即可。插错来源机会被拦下；
    **来源机只读不写**，任何情况下都不要往来源机推。

---

## 七、故障速查

| 现象 | 原因 | 处理 |
|---|---|---|
| `设备 xxx 未授权` / `没有检测到已连接的设备` | MTP（文件传输）模式下部分机型就是不给授权 | 手机 USB 用途改成「不传输数据 / 仅充电」；并允许 USB 调试 |
| `找不到 adb` | 没装 adb（本仓库不随包） | 从 https://developer.android.com/tools/releases/platform-tools 下载解压，然后设 `WECHATDBFIX_ADB` / 用 `-AdbExe`，或让它进 PATH。若放进 `tools/`，**必须连 `AdbWinApi.dll`、`AdbWinUsbApi.dll` 一起放**（只放 exe 会启动失败） |
| `ModuleNotFoundError: No module named 'cryptography'`（或 `Crypto`） | 用的解释器里没装库（多解释器机器上很常见：`python` 指到了没装库的那个） | 跑 `.\setup.ps1`；或 `-PythonExe <装了库的解释器>`；或直接 `"<解释器>" -m pip install cryptography pycryptodome` |
| `setup.ps1` 里 pip 装不上（超时/SSL/被墙） | 网络到 PyPI 不通 | 依次试：`-PipProxy http://127.0.0.1:7897`、`-PipIndex http://pypi.tuna.tsinghua.edu.cn/simple`、`-Offline`（复用系统已装的库） |
| `这台手机的微信是 8.0.xx，与 -ExpectVersion 指定的 … 不符` | 版本守卫拦下（多半插错手机） | 插对目标机；确认要推这台就加 `-AnyVersion` |
| `找不到可用的数据来源` | `data/` 里没有库，或候选都解不开 | 把库放进 `data/`；或用 `-SourceDb <文件>` |
| `table main.X has N columns but N+k values were supplied` | 起点库比来源库旧、少列（本脚本已按列名交集搬表；再出现说明列名没取到） | 属异常：请把 `output/处理报告.txt` 与报错一并提 issue |
| WAL 合并后解密 `not a database` | 该 `-wal` 与主库**不同代**（上代遗留） | 脚本会自动退回未合并版本并告警，属正常 |
| 手机微信报「数据文件损坏」并重置 | 密钥错 / 加密布局不对 / schema 被换掉 | **立即 `-Action Rollback`**，再按第五节逐条排查 |
| Python 输出中文乱码 | PS 5.1 按 GBK 解码 UTF-8 | 脚本已在原生调用处临时切 UTF-8，一般不会出现 |
| `Cannot invoke method. Method invocation is supported only on core types in this language mode`（或中文“方法调用仅支持核心类型”） | PowerShell 处于**受限语言模式**（企业锁定 / AppLocker / WDAC / JEA） | 换一个普通 PowerShell 窗口运行（`$ExecutionContext.SessionState.LanguageMode` 应为 `FullLanguage`）。本工具要写文件、要做 MD5，受限模式下会被拦 |

---

## 八、加密格式（唯一权威描述）

```
每页 1024 字节 = [密文] + [IV 16]
  页0 : salt(16) + AES-256-CBC(明文[16:1008]) + IV
  页N : AES-256-CBC(明文[0:1008]) + IV
key = PBKDF2-HMAC-SHA1(密钥字符串, salt, 4000, 32)      # salt = 文件前 16 字节
HMAC 关闭；journal_mode 保留 wal（文件头偏移 18/19 = 2,2）；reserve = 16
```

`tools/wechat_encrypt.py` 与 `tools/wechat_decrypt.py` 互为逆运算；正确性判据：
把某个加密原件的解密结果用**它自带的 salt/IV** 重加密，可**逐字节复原**该原件。

---

## 九、许可与致谢

- 本项目自写部分（`setup.ps1` / `push.ps1` / `build.ps1` / `tools/wechat_encrypt.py` / `tools/walmerge.py`）
  按仓库根目录 `LICENSE`（MIT）授权。
- `tools/wechat_decrypt.py` 来自上游开源项目，**上游未标注许可证**，本项目仅随包转发并注明来源；
  若原作者有异议请联系删除。`tools/sqlite3.exe` 为 SQLite 官方命令行工具（public domain）。
- 详见 `tools/CREDITS.txt`。

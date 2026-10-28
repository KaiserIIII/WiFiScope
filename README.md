# WiFiScope

一个仅依赖 Python 标准库的本地安全证据工作台：把 Wi-Fi 配置、本机网络状态、授权 TCP/TLS/HTTP 检查、外部扫描报告和离线抓包元数据放进可核查的调查快照。中文 Tk 界面与命令行共用证据模型；报告默认隐藏标识符，案件记录保存在本机。

[English](README.en.md) · [能力对照](docs/competitive-landscape.md) · [验证边界](docs/validation.md) · [检查方法](docs/audit-methodology.md) · [依赖审计](docs/dependencies.md)

## 直接运行

需要 Python 3.12 或 3.13。下载源码 ZIP 并解压，在包含 `wifiscope` 目录的位置打开终端。无需 pip、账户、服务器或依赖安装。

```console
python -m wifiscope
python -m wifiscope --help
python -m wifiscope demo --out demo-report
```

Windows 也可双击 `run-wifiscope.cmd`；Linux/macOS 可用 `./run-wifiscope.sh`。无图形显示或缺少 Tk 时仍可使用 CLI。Windows 的 python.org 安装程序通常提供 Tk；Linux 的 Tk 可能由系统单独打包，程序不会自动安装。macOS 本机采集不受支持，但可离线导入和使用演示。

`demo` 全部是虚构的合成证据，没有测量在线目标：包括 WPA2/开放网络、候选资产、导入扫描结果、正常验证且 14 天后到期的 TLS 1.3 证书、独立的证书验证错误，以及通过真实解析器处理的一条人工构造 HTTP 抓包。不要把演示中的时间、地址或发现视为实际观测。

## 新手三步开始

1. 启动后默认进入“新手引导”，先点“离线演示”熟悉结果，或选择“了解这台电脑”（只读配置）/“读懂已有证据文件”。程序不会在启动或切换模式时自动采集。
2. 先读执行状态、覆盖与未知，再看最多三条“先做什么”和下一步。检查指定设备时填写单个主机名/IP，可选同一主机 URL，先预览默认 80、443 及额外 URL 端口、TLS/HEAD 次数；核对后勾选底部授权并开始。底部可取消。
3. 点击底部“导出脱敏报告”生成新目录中的 JSON、CSV、HTML。需要完整表格、定制端口/范围、案件与复测比较时，随时切到“专业工作台”；当前报告和本地处置不会丢失。

[操作说明与小词典](docs/usability.md)说明隐私选择、数量比较和未知证据的含义。新手视图隐藏专业设置；原始标识符导出与案件保留仍为专业模式中的两个独立选项。CLI 参数保持不变。

## 工作台流程

1. 切换到“专业工作台”，选择“离线演示”“本机采集”，或“打开证据”（Ctrl+O）。导入必须选择 nmap、greenbone、pcap、pcapng、netsh、nmcli 或 WiFiScope JSON；XML 不会静默猜测类型。
2. 导入默认明确替换当前快照。勾选“合并到当前调查”可关联当前内存中的原始证据；独立脱敏导出的文件不能可靠合并。来源、原始观测时间与导入时间分别显示，缺失时间保持未知。
3. 先看执行状态、计划/实际连接数、剩余端点与覆盖缺口，再解释资产和发现数量。发现页支持标题/规则搜索、优先级过滤，并显示置信、检测状态、结构化证据、建议和复测条件。
4. “保存快照”写入本地 SQLite 案件，并立即重新载入数据库中的真实持久化 ID，然后才允许处置发现。“案件历史”按 100 条分页，可打开指定快照。该页的“保留原始标识符”只控制之后的案件保存。
5. “处置选中发现”记录 open、investigating、accepted-risk 或 resolved 工作流状态和本地备注。`triage_status` 与检测 `status` 分开；备注不进入普通报告。部分范围的复测不能自动证明修复。
6. “验证案件”可输入独立保存的 SHA256 head 回执；只验证本地可重算 hash 链不能证明历史未被整体替换或末尾删减。验证在后台执行，回执显示在状态栏。
7. “比较快照”在已打开案件时使用数据库快照 ID；否则选择两个 JSON 文件。仅两份均保留原始标识符时进行身份关联；其他情况显示数量/时间/覆盖对照，并解释不能关联身份。没有观察到资产代表 not-observed，不宣称已移除或已修复。
8. “导出”（Ctrl+E）输出新目录中的 JSON、CSV、独立静态 HTML；默认脱敏。“本次导出包含原始标识符”是独立于案件保存的明确选择。所有表格可滚动，界面可调整尺寸。

主动检查的范围、端口和授权复选框与 Run/Quick Audit 按钮相邻。快速配置明确显示端口 `22,80,443,445,3389,5900,8080,8443`；可编辑为较小范围。程序不会从本机网卡自动扩展扫描网段。仅检查你有权检查的明确目标。

## 命令示例

以下目录必须不存在；报告不会覆盖已有目录。文件输入最多 16 MiB，并在读取时限量。CLI 的 JSON stdout 也是导出，默认经过同一隐私投影。

```console
python -m wifiscope collect --out local-report
python -m wifiscope analyze --input wifi.txt --format netsh --out wifi-report
python -m wifiscope analyze --input wifi-linux.txt --format nmcli
python -m wifiscope import-scan --format nmap --input scan.xml --out scan-report
python -m wifiscope import-scan --format greenbone --input gmp.xml --out greenbone-report
python -m wifiscope packets --input capture.pcapng --out packet-report
python -m wifiscope probe --host 127.0.0.1 --port 8080 --attempts 1 --timeout 0.5 --authorized --out loopback-report
python -m wifiscope audit --scope 127.0.0.1 --port 8080 --deadline 300 --authorized --out audit-report
python -m wifiscope compare before.json after.json --out comparison-report
python -m wifiscope merge --input raw-local.json --input raw-scanner.json --out combined-report
```

`probe` 支持重复 `--host`、`--port` 和 `--url`（授权的 HTTP/HTTPS HEAD URL）；最多 4 主机、8 端口、每端口 5 次尝试、每族 2 个地址，总计最多 128 次连接，超时 0.2–5 秒。DNS 固定一次解析，正常 TLS 验证，不降级、不跟随重定向、不读取正文、不保存 Cookie 值。443 端口会增加一次 TLS 诊断；显式 URL 会增加 HEAD 连接。TCP 连接耗时与失败率不等于带宽或网络丢包率。

`audit` 接受重复 `--scope IP_OR_CIDR`（最多合计 64 个 IP）与重复 `--port`；省略端口使用上述快速配置。每批最多 4 主机，每端口 1 次，默认超时 0.5 秒，整个运行默认/最长截止 300 秒，连接速率最多 4 次/秒，批次之间有可取消的至少 0.25 秒边界等待。完整 64 主机快速配置计划 512 次 TCP 加最多 64 次 TLS，按 4 次/秒规划估算约 144 秒（首次连接可立即开始，实际耗时可能更短或更长）；截止时间不保证完成。规划在开始前打印到 stderr。Ctrl+C/取消与截止保留已获得观测、执行状态及未检查范围，不重复本机采集。DNS 错误是已尝试但未解析，不能当作成功检查。

退出码：0 表示命令完成（包括观察到拒绝连接或风险）；1 表示审计部分完成/截止或案件验证失败；2 表示参数、输入、权限或输出错误；130 表示取消。风险数量本身不作为进程失败条件。

## 案件与持久化 ID

```console
python -m wifiscope case add --db investigation.db --input demo-report/report.json
python -m wifiscope case list --db investigation.db --limit 100 --offset 0
python -m wifiscope case show --db investigation.db --snapshot 1 --include-identifiers
python -m wifiscope case triage --db investigation.db --snapshot 1 --finding PERSISTED_FINDING_ID --status investigating --note "Local review"
python -m wifiscope case show --db investigation.db --snapshot 1
python -m wifiscope case verify --db investigation.db
python -m wifiscope case verify --db investigation.db --expected-head TRUSTED_SHA256_HEAD
python -m wifiscope case compare --db investigation.db 1 2 --out case-comparison
```

把 `PERSISTED_FINDING_ID` 替换为前一个 `case show --include-identifiers` 输出的 `investigation.findings[].id`。该开关允许查看原样的持久化 ID；默认保存时它仍是伪名。普通 show 再次随机化 ID，不能拿新导出的 ID 处置存储快照。PowerShell 可这样读取持久化 ID，避免手工抄写：

```powershell
$caseView = python -m wifiscope case show --db investigation.db --snapshot 1 --include-identifiers | ConvertFrom-Json
$caseFinding = $caseView.investigation.findings[0].id
python -m wifiscope case triage --db investigation.db --snapshot 1 --finding $caseFinding --status investigating
```

身份关联需要在最初导出时选择 `--include-identifiers`，并在 `case add` 时再次明确选择 `--include-identifiers`；这是两项独立决定。已脱敏输入无法恢复原始标识符，即使重新导出/保存时选择包含标识符，其 `identifiers_included` 仍为 false，比较仅显示数量，合并会拒绝。案件默认脱敏也保留已构建的资产/发现/覆盖，不重新用伪名当作 IP 重建。

## 能力与限制

- Windows 只读适配器：netsh Wi-Fi、PowerShell 网卡/默认路由/防火墙；系统权限或位置隐私限制会成为缺口，不会自动提权。Windows 位置访问或无线服务禁用时，可启用相应系统权限后重试，或离线导入 netsh 输出。
- Linux：nmcli 缓存 Wi-Fi 列表、`ip -j` 地址及 IPv4/IPv6 默认路由；DNS 配置和防火墙当前标记不可用。Linux 适配器目前由合成 fixtures 验证，未因离线 CI 就宣称本机 Linux 采集已验证。命令缺失/超时是缺口。
- Nmap XML 与 Greenbone GMP XML 是外部扫描证据导入，不会自动运行扫描器。服务版本、CVE 和评分来自外部结果，维持 imported-unverified；不内置全面 CVE 数据库、漏洞利用或凭据审计。
- PCAP/PCAPNG 为离线有界元数据解析，支持常见 Ethernet/VLAN/IPv4/IPv6/ARP 和 TCP/UDP 计数、HTTP 明文请求提示、DNS 查询/NXDOMAIN、ARP 冲突提示；不抓包、不重组、不保存载荷/URI/DNS 名称/凭据，不是 Wireshark、IDS 或完整协议解码器。ARP 冲突也可能来自 HA、代理 ARP、地址复用。
- Wi-Fi 信号是观测值，信道分布不等于干扰测量；不执行断连、破解或密钥读取。代理存在仅作为环境上下文。
- 默认导出对身份字段使用每次导出独立的 HMAC 伪名，保留允许的类型化测量；HTML 转义、CSV 公式前缀中和、不载入外部资源。脱敏是数据最小化，不保证匿名，时间/拓扑/服务仍可能识别环境。原始输入文件不会被擦除。
- 案件是本地 SQLite，事件追加且快照不可变；hash 链没有签名，不能抵抗有能力重写整库的攻击者。Windows ACL 不作保证。自行保护案件与原始报告，并将可信回执独立保存。
- 取消是协作式：网络等待会轮询取消；本机命令、离线解析和原子案件写入可能需要先完成当前有界操作。状态栏会区分进行中、取消、部分、截止和完成；取消不撤销已完成的持久化写入。

干净报告不能证明安全。请结合相同授权范围的独立复测、配置审查和专业扫描工具。[安全问题报告](SECURITY.md) · [贡献说明](CONTRIBUTING.md) · [更新记录](CHANGELOG.md)

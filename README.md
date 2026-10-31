# WiFiScope

一个仅依赖 Python 标准库的本地安全证据工作台：结合 Wi-Fi/本机配置、授权 TCP/TLS/HTTP 检查、扫描报告、本地 CVE 候选审计、有界实时抓包和定点 Wi-Fi 信号调查。中文 Tk 界面与 CLI 共用类型化证据；报告默认隐藏标识符，案件保存在本机。

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

## 四项安全工具

新手与专业模式顶部均提供“漏洞库与资产清单”“漏洞审计”“实时抓包”“Wi-Fi 热力图”。工具窗口可滚动，底部应用、取消和导出保持可见。打开、切换或定位不会自动采集/探测；离线演示均为明确标记的合成数据，由实际本地引擎处理。

- 漏洞库与资产清单：从 1..64 个明确选择的本地 NVD 文件新建 SQLite 索引，或打开已有索引，每页浏览 20 条。选择详情中的字面 CPE/CNA 身份，再填写自己的资产标签和版本，无需手写 JSON/CPE。也可导入 schema1、CycloneDX JSON 1.6/1.7、SPDX JSON SPDX-2.3 的显式 CPE 2.3，或明确选 `nmap` 导入本地 XML 的显式 CPE 主张（有限 URI/格式化 profile）。源文件 ≤16 MiB、保留 ≤1024 资产/8192 组件。预览逐主机地址、服务/OS 假设和来源时间；可明确设置所选组件的分析排序，默认 `unknown`，不是扫描发现。预览后明确应用/导出。原演练保留；新增 Nmap 合成演练含两台虚构主机、探测服务及互斥 OS 假设。见[格式、隐私、限制与实测容量](docs/catalogs.md)。

```console
python -m wifiscope catalog audit --db LOCAL.db --inventory scan.xml --inventory-format nmap --out NEW_NMAP_REPORT
```

仅读取已有本地文件，不运行 Nmap。默认使用共享 HMAC 脱敏；`--include-identifiers` 是明确的原始身份导出选择。历史源提交 `d676fdd` / 公开提交 `54112f97` 的 25 年度文件索引已收录 416321 条；收录不等于可评估或设备漏洞。来源错误/缺少完成状态及工作限额仍给出部分结果，未评估数量可保持未知。未证明安装、可利用性或完整年度清单覆盖。

- **漏洞审计**：先载入证据，再选择内置 6 CVE 复核子集或本地 native/NVD2 JSON（可选 SHA256），明确点击审计。结果显示目录版本/哈希/来源/复核日、版本范围、置信和未知服务。候选需要核查发行版回补与配置；无匹配不表示安全。
- **实时抓包**：明确枚举并选择接口，核对默认 10 秒/2000 包/8 MiB/96 字节/非混杂计划，再勾选相邻授权。修改计划清除授权。>96 字节或原始文件另需独立同意，可能含私人应用数据；文件必须是新路径，普通报告只包含元数据。Windows 需要已安装 Npcap 及权限；Linux 需要 libpcap 或 AF_PACKET 权限；不自动安装。
- **Wi-Fi 热力图**：填写明确网络（优先 BSSID）和 %/实测 dBm，创建项目，在空白画布或本地 PNG/GIF 上点击定位，再点“采样此位置”读取一次本地配置。背景 ≤8 MiB、每轴 ≤8192、≤3200 万像素，仅本地显示。归一化坐标不随缩放/平移变化；未知不补值，IDW 估计只在有三个局部贡献点的凸包支持区域显示。支持本地项目新文件保存、JSON/CSV 导入、可撤销移点与独立 SVG 导出。

工具结果先保存在独立预览，不改当前报告、案件 ID 或处置。应用前可先保存案件，勾选相邻替换选择后点击“应用工具结果”；不会静默混合不同上下文。工具导出在两种模式均可用，默认 HMAC，原始标识符复选框与主窗口及案件保留独立。背景图片/路径、原始包文件/路径、应用载荷、本地备注和任意导入描述均不进入普通报告；原始标识符选项也不会放行这些内容。

合成调查不能保存为会丢失合成标记的本地项目；请使用“导出工具结果”保留报告标记。非合成项目仍可独占保存/打开。JSON、CSV 或演示成功替换项目后，旧项目的撤销历史会清空。

```console
python -m wifiscope vuln --input REPORT.json --out NEW_VULN_REPORT
python -m wifiscope vuln --input REPORT.json --catalog PACK.json --catalog-format native --catalog-sha256 EXPECTED_SHA256 --out NEW_CATALOG_REPORT
python -m wifiscope vuln --input REPORT.json --catalog NVD.json --catalog-format nvd2
python -m wifiscope capture --list-interfaces
python -m wifiscope capture --interface "EXACT_LISTED_INTERFACE" --duration 10 --max-packets 2000 --max-bytes 8388608 --snaplen 96 --authorized --out NEW_CAPTURE_REPORT
python -m wifiscope capture --interface "EXACT_LISTED_INTERFACE" --filter "tcp port 443" --authorized --out NEW_FILTERED_REPORT
python -m wifiscope capture --interface "EXACT_LISTED_INTERFACE" --snaplen 65535 --retain-packets --raw-out NEW_CAPTURE.pcap --authorized --out NEW_RAW_METADATA_REPORT
python -m wifiscope survey --input samples.csv --format csv --grid-size 40 --radius .35 --power 2 --out NEW_SURVEY_REPORT
python -m wifiscope survey --input project.json --format json --include-identifiers --out NEW_EXPLICIT_ID_REPORT
```

不要原样运行接口占位符；先枚举后选择获授权接口。详见[漏洞引擎](docs/vulnerability-engine.md)、[实时抓包](docs/live-capture.md)、[Wi-Fi 调查](docs/wifi-survey.md)。调查 CSV 必须使用 `x,y,value,observed_at,ssid,bssid,metric`，不是导出的扁平报告 CSV；空 value 表示未知。

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

以下目录必须不存在；报告不会覆盖已有目录。证据/SBOM 输入最多 16 MiB；索引目录源文件使用[独立的源/展开限制](docs/catalogs.md)。CLI 的 JSON stdout 也是导出，默认经过同一隐私投影。

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
- PCAP/PCAPNG 支持有界离线元数据解析；实时抓包另有明确接口/限额/授权流程。支持常见 Ethernet/VLAN/IPv4/IPv6/ARP 与 TCP/UDP、HTTP 请求提示、DNS 查询/NXDOMAIN、ARP 冲突提示；不重组、不将载荷/URI/DNS 名称/凭据写入报告，不是完整 DPI、IDS 或 Wireshark。ARP 冲突也可能来自 HA、代理 ARP、地址复用。
- Wi-Fi 信号是观测值，信道分布不等于干扰测量；不执行断连、破解或密钥读取。代理存在仅作为环境上下文。
- 默认导出对身份字段使用每次导出独立的 HMAC 伪名，保留允许的类型化测量；HTML 转义、CSV 公式前缀中和、不载入外部资源。脱敏是数据最小化，不保证匿名，时间/拓扑/服务仍可能识别环境。原始输入文件不会被擦除。
- 案件是本地 SQLite，事件追加且快照不可变；hash 链没有签名，不能抵抗有能力重写整库的攻击者。Windows ACL 不作保证。自行保护案件与原始报告，并将可信回执独立保存。
- 取消是协作式：网络等待会轮询取消；本机命令、离线解析和原子案件写入可能需要先完成当前有界操作。状态栏会区分进行中、取消、部分、截止和完成；取消不撤销已完成的持久化写入。

干净报告不能证明安全。请结合相同授权范围的独立复测、配置审查和专业扫描工具。[安全问题报告](SECURITY.md) · [贡献说明](CONTRIBUTING.md) · [更新记录](CHANGELOG.md)

## 可继续的保存审计

“漏洞库与资产清单”保留原来的一次性预览和两个合成演练，并新增 **保存审计**。先明确打开本地目录并准备清单，选择不存在的本地保存文件，再勾选“我明确同意在本机保存原始标识符与证据”，点击 **新建保存审计**。默认每批保留 256 个候选结果；专业详细设置可改为 1..4096。原始本机存储同意默认未勾选，与导出的原始标识符选项分开。

**继续一批** 每次只运行一批，保留以前的页；关闭后可选择文件并 **打开保存审计**。继续使用文件里的冻结清单与证据，不使用后来编辑的面板清单，且需明确选择原来内容完全相同的目录。**上一结果页 / 下一结果页** 仅切换预览；须另行勾选替换选择并点击原有“应用工具结果”，才会替换当前报告。打开、继续和整次导出不会自动改变当前报告、案件、快照或面板清单。**导出整次审计** 写入一个不存在的新目录；默认全页共享同一组 HMAC 脱敏标识符，独立页导出之间则不能可靠关联。

```console
python -m wifiscope catalog run start --db catalog.db --inventory inventory.json --run new-run.db --store-raw-identifiers
python -m wifiscope catalog run continue --db catalog.db --run new-run.db
python -m wifiscope catalog run status --run new-run.db
python -m wifiscope catalog run page --run new-run.db --number 1 --out new-page-bundle
python -m wifiscope catalog run export --run new-run.db --out new-run-bundle
```

新建和继续只推进一批：退出码 0 表示所选范围计算完成且来源完整，1 表示暂停、受阻、整次限额或来源部分，130 表示取消，2 表示输入/输出错误。成功的 status/page/export 读取返回 0，页报告仍明确标为部分范围。完成只说明所选目录/输入流已处理，不表示网络安全或漏洞已确认。具体标志、有限存储和信任边界见 [目录说明](docs/catalogs.md#saved-audits)。

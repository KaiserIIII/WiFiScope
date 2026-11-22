# 网络工作台

从 WiFiScope 顶栏打开「网络工作台」。使用标签切换报文、诊断和设备视图。点击图上的点或拓扑关系可以选中对应的表格行，右侧显示该条证据。桌面界面和 CLI 都可将当前结果导出为本地 HTML、JSON、CSV，默认对地址、设备、接口等身份字段使用同次导出内一致的伪名。

## 报文分析

打开 PCAP 或 PCAPNG 文件，也可以从「实时抓包」的结果打开时间线。使用协议、关键字和分页浏览。时间线优先使用相对抓包时间，缺失时使用帧序号。交互编号仅在同一次抓包内有效。

可查看 ARP、ICMPv4/v6 Echo、TCP 握手和重复 SYN、DHCPv4、DNS、明文 HTTP/1.x 及可见的 TLS 记录。截断、分片、只观察到一个方向及缺失包都会影响匹配。TLS 1.3 的某些加密握手消息也使用外层 Application Data 类型。原生解析按包读取元数据，不重组或解密，默认报告不含正文、DNS 名称、SNI 或 Cookie。

选择本机已有的 TShark 可以在工作台浏览其解析出来的帧号、相对时间、长度与协议栈。选择本机 Wireshark 可以打开其完整离线查看器。两项都由用户选定工具和文件，WiFiScope 不安装依赖。

## 诊断与监测

「仅看本机」读取接口、地址、完整路由表、邻居缓存和监听端口。可在 Windows 与具备相应命令的 Linux 上使用，各平台的可用字段由本机权限和工具决定。

主动诊断可以填写网关、对端、DNS、跟踪目标、HTTP(S)、NTP、DoH。点「预览计划」，核对目标后勾选授权开始。修改参数会清除预览授权。未填写的目标保持未请求。Windows IPv4 跟踪在要求绑定来源地址时可能显示不可用。

「开始监测」按计划运行 1–60 轮，逐轮更新趋势和结果。达到连续失败阈值或明确恢复时，生成本机告警记录。取消可保留已完成样本。检查可被 ICMP 策略、DNS 或应用配置影响，结合各阶段证据定位。图中的时延对应该阶段首个成功测量，单位为毫秒。

## 设备与拓扑

从设备终端保存含命令和提示符的本地文本，例如 Cisco IOS 的 show vlan brief、show interfaces trunk、show ip route、show ip ospf neighbor、show ip ospf interface、show ip ospf database、show lldp neighbors 和 show running-config。支持 UTF-8 和 GBK。

「设备与拓扑」可查看 VLAN 端口、路由、OSPF 与 LLDP 邻接。图上只显示文本证据中的关系。导入同一设备的基线，再比较当前证据，可以看到端口、路由开销与下一跳变化。部分证据不会被当成设备或路由已移除。「配置预览」从记录提取已支持的 VLAN、端口、地址和 OSPF 参数，供离线核对。

## CLI

~~~
python -m wifiscope network timeline --input lab.pcap --out new-packet-report
python -m wifiscope network dissect --input lab.pcapng --out new-decode-report
python -m wifiscope network device --input switch.txt --out new-device-report
python -m wifiscope network compare before.txt after.txt --out new-comparison
python -m wifiscope network diagnose
python -m wifiscope network diagnose --trace 192.0.2.1 --preview --include-identifiers
python -m wifiscope network monitor --peer 192.0.2.1 --samples 5 --interval 2 --authorized --out new-monitor-report
~~~

192.0.2.1 是文档示例地址。实际运行主动检查时使用明确授权的目标。导出目录必须是新路径。默认 JSON 和三格式报告使用同一脱敏规则，可用 --include-identifiers 显式保留标识符。

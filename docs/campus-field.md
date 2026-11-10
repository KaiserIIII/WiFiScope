# 校园网接入体检

从 WiFiScope 顶部打开「校园网体检」，点「读取当前连接」。Windows 会读取已关联的 Wi-Fi、本机地址、默认路由、DNS、DHCP 租期、防火墙和监听端口。Linux 按可用的本机工具读取链接和路由。系统权限或工具不足时，报告列出缺失项。

复测前核对网关 IP、门户 URL 和对端地址，再勾选授权。默认网关端口为 22、23、830。网关识别只读连接建立后服务端主动发送的有限字节。界面显示 TCP 状态、识别到的协议以及是否收到 Telnet 登录提示。SSH 版本横幅是协议线索。门户用 HEAD 逐次记录 HTTP 状态和是否带重定向头，保留原始地址不跳转。页面表单、凭据提交和登录状态要用单独的证据核实。

对端抽测接受最多八个明确的 IP。它记录 ICMP 回包、TCP 状态和同一接口上的邻居缓存。多个地址共享网关 MAC 可能来自代理 ARP 或集中转发。TCP 超时可能来自终端离线、主机防火墙或网络策略，报告会把隔离状态保留为未定。点「导出工具结果」保存独立 JSON，默认以本次导出内稳定的伪名替代地址、SSID 和接口标识。要保存真实标识需明确勾选。原始报文、配对码、门户响应正文及 Cookie 不进入报告。

## CLI

在两种界面模式都可以打开体检窗口。需要指定来源 IP、端口、重复次数或出口对照时，使用 CLI。下列地址为占位示例，按实际授权范围填写。

```console
python -m wifiscope field audit --out local-field.json
python -m wifiscope field audit --interface WLAN --source 192.0.2.20 --gateway 192.0.2.1 --portal http://192.0.2.2/ --peer 192.0.2.21 --samples 3 --authorized --out campus-field.json
```

`--gateway-port`、`--peer-port`、`--portal`、`--peer` 可重复。指定 `--interface` 并开启主动检查时，也要提供属于该接口的 `--source`。未指定源地址时，系统选择出站路由。可选 `--dns` 和 `--ntp` 对明确指定的数字 IP 发出有界 UDP 请求，`--doh` 和 `--download` 使用明确指定的 HTTPS URL。DNS 和 DoH 测试只查询固定示例域名。出站结果仅覆盖所选目标和地址族。下载结果使用最多 1 MiB 的样本，连接和握手时间计入测量。用 `--help` 查看参数，文件必须是现有目录里的新路径。

## 用两台设备判定互访

1. 让两台获准测试的设备接入同一 Wi-Fi，分别确认本机 IP。在 B 上运行 `field listen`，用 B 的地址作绑定地址，A 的地址作预期来源。终端显示临时端口和配对码。
2. 在 A 上运行 `field check`，指定 B 的地址、端口以及 A 的源地址，按提示输入配对码。
3. `handshake_verified` 表示本方向交换了带校验的请求和应答。交换 A/B 角色可检查反向发起连接。负结果需对照 B 的监听状态、防火墙及 AP。仅靠超时无法判定隔离。

```console
python -m wifiscope field listen --bind 192.0.2.21 --expect-peer 192.0.2.20 --seconds 90 --authorized
python -m wifiscope field check --source 192.0.2.20 --target 192.0.2.21 --port 49152 --authorized
```

这里的 49152 是占位端口，使用 B 实际显示的值。监听绑定到单一地址和临时端口，只接受预期来源及校验通过的会话。配对通过、到期或取消时会关闭监听。用同 AP 和跨 AP 两组结果分别记录测量范围。

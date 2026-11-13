# Network Sniffer

Network Sniffer 是一个面向 Windows 的图形化抓包和协议分析工具。它能实时捕获网卡和本机回环流量，打开 PCAP/PCAPNG 文件，并按 TCP 会话或本机进程追踪报文。

## 功能

- 支持实体网卡及 IPv4、IPv6 回环抓包。接口列表显示收发速率曲线。
- 报文列表、协议树和 HEX/ASCII 视图联动。支持 Ethernet、802.1Q VLAN、ARP、IPv4/IPv6、TCP、UDP、ICMP、DNS、HTTP/1.x 和 TLS。
- 提供采集筛选、显示筛选、自定义着色和基于捕获的 DNS 回答生成的主机名提示。
- 支持双向 TCP 时间线与载荷重组、本机 PID 查询和地址对流量汇总。
- 查看 TLS 记录和证书，可用对应密钥日志解密支持的 TLS 1.3 会话。
- 提供 Wireshark extcap 接口，可按本机 PID 采集 TCP 流量。

## 构建与启动

需要 Windows 11 x64、.NET 10 SDK 和 PowerShell。实时抓包需要管理员权限。构建出的自包含发布包附带 .NET/WPF 运行时和 WinDivert 组件。

```powershell
git clone https://github.com/Wzhongkai/ex1a-network-sniffer.git
cd ex1a-network-sniffer
dotnet build .\Sniffer.slnx -c Release
.\scripts\Publish.ps1
.\artifacts\release\Sniffer.Desktop.exe
```

打包结果位于 `artifacts/`。分发或移动程序时，请保留 `release/` 下的全部文件。实体网卡通过 Windows Packet Monitor 采集，IPv4 回环通过 Winsock 采集，IPv6 回环和 TCP 流事件通过随包附带的 WinDivert 采集。

## 抓包与分析

1. 初次使用可以点「载入演示流量」。选择第 6 帧，打开「跟踪所选 TCP 流」，可查看乱序重组后的 HTTP 请求及对向响应。
2. 实时抓包时选网卡或回环接口，填写可选的采集表达式并开始捕获。分析已有抓包时，点「打开抓包」选择 PCAP 或 PCAPNG。
3. 用「协议筛选」或「显示表达式」缩小范围。选择报文后，点击协议树里的字段可高亮对应字节。「连接汇总」可查看按地址对统计的收发流量与进程。
4. 「保存抓包」导出当前可见、仍在历史缓冲中的报文。涉及多种链路类型时选 PCAPNG。

| 用途 | 表达式 | 输入位置 |
| --- | --- | --- |
| 抓取双向 TCP 8080 流量 | `tcp and port 8080` | 采集筛选 |
| 抓取发往指定端口的 UDP | `udp dst port 46071` | 采集筛选 |
| 查看 IPv6 TCP 或 ICMPv6 | `ipv6 && (tcp \|\| icmpv6)` | 显示表达式 |
| 查找指定进程的 HTTP 报文 | `http && pid == 1234` | 显示表达式 |
| 查看指定 TCP 会话 | `stream == 1` | 显示表达式 |

采集筛选在用户态、流追踪前生效。分析会话时，采集条件应保留双向报文。普通的离线抓包文件缺少本机 PID 信息。

### TLS

选中 TLS 报文，打开「跟踪所选 TCP 流 → TLS 记录与证书」。如需查看 TLS 1.3 明文，加载客户端或服务端为该连接主动导出的 `SSLKEYLOGFILE`。本地解密支持 AES-GCM 和 ChaCha20-Poly1305，并受每方向 32 KiB TCP 重组窗口及捕获完整性限制。导出的抓包文件保留原始字节。

### Wireshark extcap

发布后，将 `artifacts/extcap/` 中的 EXE、DLL 和 SYS 复制到 Wireshark 的个人 Extcap 目录，可在「关于 Wireshark → 文件夹」找到该位置。以管理员身份启动 Wireshark，选择 `TCP by PID` 接口并设置 `Local process ID`。 [Wireshark extcap 开发指南](https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html)

## 测试

```powershell
dotnet run --project .\tests\Sniffer.Checks -c Release --no-build -- offline
dotnet run --project .\tests\Sniffer.Checks -c Release --no-build -- live
dotnet run --project .\tests\Sniffer.Checks -c Release --no-build -- traffic
```

`offline` 检查抓包文件读写、协议解析、过滤和 TCP 重组。`live` 需要管理员权限，用于验证 IPv4/IPv6 回环和进程归属。`traffic` 生成本地测试流量并打印 PID。发布后，可在管理员 PowerShell 中运行 `.\scripts\Verify-Extcap.ps1 -Tshark <tshark.exe 路径>` 验证 Wireshark 扩展。

## 项目结构

| 路径 | 内容 |
| --- | --- |
| `src/Sniffer.Core` | 协议解析、过滤、TCP 重组与抓包文件读写 |
| `src/Sniffer.Windows` | Windows 实时采集与进程归属 |
| `src/Sniffer.Desktop` | WPF 界面 |
| `src/Sniffer.Extcap` | Wireshark PID 采集接口 |
| `tests/` 和 `scripts/` | 测试与发布脚本 |

第三方组件及授权见 [第三方组件](vendor/第三方组件.md)。

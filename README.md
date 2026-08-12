# Rust OS 网络栈功能扩展与 Linux 兼容性增强

队伍名称：88博弈  
所属赛题：Proj12  
所属高校：吉林大学  
项目成员：俞俊升、童旭光、孙威  
指导教师：宋姗姗、郭佳妮

## 文档与演示

- [技术文档](docs/技术文档-Rust%20OS%20网络栈功能扩展与%20Linux%20兼容性增强.docx)
- [进度汇报 PPT](docs/进度汇报-Rust%20OS%20网络栈功能扩展与%20Linux%20兼容性增强.pptx)
- [进度汇报 PDF](docs/进度汇报-Rust%20OS%20网络栈功能扩展与%20Linux%20兼容性增强.pdf)

> **视频文件较大，无法上传完整视频至平台。可通过以下地址观看项目演示视频及决赛展示视频（分P）：**
>
> **【操作演示视频（Rust OS 网络栈功能扩展与 Linux 兼容性增强---Proj12）】**
>
> https://www.bilibili.com/video/BV1LpTw6DETN/?share_source=copy_web&vd_source=9d6745e0ab38139840865d59e701a2f0

## 项目背景

星绽操作系统（Asterinas）是一个以 Rust 为主要实现语言、面向 Linux ABI 兼容目标的操作系统内核。其网络能力基于 smoltcp 和内部 `aster-bigtcp` 抽象构建，具有结构清晰、资源可控和安全性较强等特点。

但 smoltcp 本身面向轻量级、嵌入式和 no_std 场景，并不完整复刻 Linux 网络语义。因此，在运行常见 Linux 网络程序时，Asterinas 原有网络栈仍存在一些能力缺口：

- 缺少 IP raw socket，导致 `ping` 等依赖 ICMP raw socket 的工具无法正常运行；
- `0.0.0.0` / `INADDR_ANY`、`listen()`、`getsockname()`、`SO_REUSEADDR` 等 socket 语义与 Linux 不一致，影响 Flask、Python HTTP server、Redis 等服务启动和运行；
- 缺少类似 Linux netfilter/iptables 的包处理框架，难以支撑基础包过滤与 NAT 场景。

本项目围绕“Rust OS 网络栈功能扩展与 Linux 兼容性增强”目标，从协议访问能力、socket 接口语义和内核级包处理框架三个层次对 Asterinas 网络栈进行扩展。

## 完成情况

| 技术指标 | 当前实现 | 主要验证 | 当前边界 |
|---|---|---|---|
| Raw Socket 与 ping | IPv4/IPv6 Raw Socket、ICMP/ICMPv6、`IP_HDRINCL`/`IPV6_HDRINCL`、路由感知发送、非阻塞与事件通知 | Raw Socket 回归、IPv4/IPv6 loopback、路由与外网 Ping 验证 | 尚未覆盖 Linux Raw Socket 的全部选项、flag、分片重组和协议族语义 |
| Linux Socket 语义兼容 | `INADDR_ANY`、隐式 `listen()`、`getsockname()`、多网卡 TCP/UDP 收发、事件汇聚与 `SO_REUSEADDR` | 单点回归、Ubuntu/原始/当前 Asterinas 131 项对照、Flask 双网卡生命周期验证 | TCP/UDP 服务兼容仍以 IPv4 常见场景为主；`SO_REUSEPORT`、完整 backlog 和高级 Socket 选项仍待完善 |
| Netfilter、连接跟踪与 NAT | IPv4/IPv6 Hook、过滤规则、计数器、iptables/ip6tables 控制面、NEW/ESTABLISHED 跟踪、SNAT/MASQUERADE/DNAT 与反向转换 | 规则生命周期回归、双网卡转发拓扑、IPv4/IPv6 过滤与有状态 NAT 场景 | 属于可验证子集，尚非完整 iptables/nftables ABI、完整 conntrack 或生产级规则规模 |

## 功能

### 技术指标一：Raw Socket 支持与 ping 可用性

本项目实现了 IPv4/IPv6 Raw Socket 的可用子集，使 `ping`、`ping -6` 和协议级网络诊断具备内核基础。

主要能力包括：

- 支持 `AF_INET / SOCK_RAW` 与 `AF_INET6 / SOCK_RAW`，覆盖 ICMP、ICMPv6 及多协议 Raw Socket；
- 创建 raw socket 时进行 `CAP_NET_RAW` 权限检查；
- IPv4 接收方向向用户态交付完整 IP packet，并完成 ICMP Echo Request/Reply 收发闭环；
- 支持 ICMPv6 loopback Echo、IPv6 Raw 协议收发和基础以太网/NDP 路径；
- 根据目标地址查询路由并选择实际出口接口，避免 Raw Socket 固定使用默认网卡；
- 支持 `IP_HDRINCL`、`IPV6_HDRINCL` 及基础 ancillary option；
- 支持 `IP_RECVERR` / `IPV6_RECVERR` 本地错误队列基础语义；
- 支持 Raw Socket 的非阻塞读写、`poll` readiness 和等待线程唤醒；
- 对 raw packet 接收/发送队列设置 packet 数量和字节数上限，避免无界资源占用。

### 技术指标二：smoltcp 与 Linux 网络接口语义差异修复

本项目以 Flask、Python HTTP server、Redis 和典型 TCP/UDP server 的完整生命周期为目标，修复 Asterinas 与 Linux 在 IPv4 Socket 语义上的关键差异。

主要能力包括：

- 将 TCP/UDP `bind(0.0.0.0:<port>)` 解释为 Linux `INADDR_ANY`，展开为全部本地 IPv4 接口上的同端口绑定；
- 在所有接口上原子预留端口，任一接口冲突时整体回滚，避免产生部分绑定；
- 汇聚各接口 TCP Listener，使一个用户态 Socket 能从 loopback、eth0、eth1 等任意接口接收连接；
- `getsockname()` 保留用户可见端点，例如 `0.0.0.0:<actual-port>`；
- 支持未显式 `bind()` 的 TCP socket 直接 `listen()`，自动绑定到 `INADDR_ANY:ephemeral`；
- 保持具体地址的精确绑定语义，例如 `127.0.0.1` 仅通过 loopback 提供本机访问；
- 为 TCP `connect()`、UDP `sendto()` 按目标地址和路由动态选择接口，并汇聚 UDP 多接口接收队列；
- TCP 连接失败后恢复完整通配绑定集合，支持重新选路连接；
- 聚合各接口 `IoEvents` 与等待队列，使 `poll/select/epoll` 统一反映逻辑 Socket 的可读、可写状态；
- 保持非阻塞 `accept()` / `recv()` 在无连接或数据时返回 `EAGAIN`；
- 关闭时释放全部内部 Socket 与端口预留，并支持 `SO_REUSEADDR` 下同端口快速重启；
- 调整默认 Socket buffer，并验证 64 KiB HTTP 响应能够完整传输；
- 明确边界：指标二的 TCP/UDP 通配兼容以 IPv4 常见服务场景为主，不能据此推断整个系统不支持 IPv6。

### 技术指标三：Netfilter、连接跟踪与 NAT

本项目在 Asterinas 数据路径中实现了可验证的 Netfilter/iptables 子集，并将其扩展到 IPv4/IPv6 转发、有限连接跟踪和有状态 NAT。

主要能力包括：

- 在 IPv4/IPv6 ingress、local 和 forwarding 数据路径接入 Netfilter Hook；
- 定义 `PREROUTING`、`LOCAL_IN`、`FORWARD`、`LOCAL_OUT`、`POSTROUTING` Hook 点；
- 支持 filter 表 `INPUT`、`OUTPUT`、`FORWARD` 链、链策略、规则插入/替换/删除/清空和 first-match 语义；
- 支持 ICMP/ICMPv6/TCP/UDP、IPv4/IPv6 地址、端口和 ICMP 标识等匹配条件；
- 支持 `ACCEPT` / `DROP` target；
- 支持规则 packet/byte counters；
- 支持 TCP/UDP 的 `NEW` / `ESTABLISHED` 有限连接跟踪与 `-m conntrack --ctstate`；
- 支持 IPv4 TCP/UDP/ICMP 的 SNAT、MASQUERADE、DNAT、端口改写及返回路径反向转换；
- 支持 IPv6 ICMPv6/TCP/UDP 的地址级 SNAT、MASQUERADE、DNAT 和有界状态表；
- 提供 `/proc/netfilter_rules` 控制面；
- 提供最小用户态 `iptables` shim，并在控制面接受相应 `ip6tables` 子集；
- 支持双网卡 IPv4/IPv6 转发拓扑、方向性过滤与 NAT 场景验证。

## 代码结构

以下只列出本项目开发或修改的关键位置，未列出的目录主要为 Asterinas 原有代码。

### 技术指标一：Raw Socket

| 路径 | 类型 | 说明 |
|---|---|---|
| `kernel/src/syscall/socket.rs` | 修改 | 分发 IPv4/IPv6 Raw Socket 创建请求 |
| `kernel/src/net/socket/ip/raw.rs` | 新增 | IPv4 Raw Socket、权限、路由、收发、`IP_HDRINCL`、ancillary option 与错误队列 |
| `kernel/src/net/socket/ip/raw_v6.rs` | 新增 | IPv6 Raw Socket、ICMPv6、`IPV6_HDRINCL`、路由与错误队列 |
| `kernel/src/net/socket/ip/raw_observer.rs` | 新增 | Raw Socket readiness 观察器与等待唤醒 |
| `kernel/src/net/socket/ip/options.rs` | 修改 | IPv4/IPv6 Raw Socket 选项状态 |
| `kernel/src/net/router.rs` | 修改 | IPv4/IPv6 目标路由与出口接口查询 |
| `kernel/src/net/socket/netlink/route/` | 修改 | 导出接口地址和 IPv4/IPv6 路由信息 |
| `kernel/libs/aster-bigtcp/src/socket/raw_ip.rs` | 新增 | 按协议维护 Raw IP 收发队列和有界资源 |
| `kernel/libs/aster-bigtcp/src/socket_table.rs` | 修改 | 按 IP 协议注册、查找与投递 Raw Socket |
| `kernel/libs/aster-bigtcp/src/iface/poll.rs` | 修改 | Raw packet ingress/egress、本地 ICMP/ICMPv6 与路由发送路径 |
| `test/initramfs/src/regression/network/icmp_raw_socket.c` | 新增 | IPv4 Raw Socket、多协议、HDRINCL、错误队列和非阻塞回归 |
| `test/initramfs/src/regression/network/ipv6_any.c` | 修改 | IPv6 Raw、ICMPv6、HDRINCL 和错误队列回归 |
| `test/initramfs/src/regression/network/ping_loopback.sh` | 新增 | `ping` 命令级回归测试 |

### 技术指标二：Linux Socket 语义兼容

| 路径 | 类型 | 说明 |
|---|---|---|
| `kernel/src/net/socket/ip/common.rs` | 修改 | 识别 `INADDR_ANY`、枚举接口并管理跨接口原子端口预留 |
| `kernel/src/net/socket/ip/addr.rs` | 修改 | 分离内部绑定端点和用户可见端点 |
| `kernel/src/net/socket/ip/stream/init.rs` | 修改 | TCP 通配绑定、隐式 `listen()`、跨接口端口分配和连接选路 |
| `kernel/src/net/socket/ip/stream/listen.rs` | 修改 | 汇聚多接口 Listener、`accept()` 与 readiness |
| `kernel/src/net/socket/ip/stream/connecting.rs` | 修改 | 连接失败后恢复通配绑定集合 |
| `kernel/src/net/socket/ip/stream/connected.rs` | 修改 | 记录实际进入接口地址并适配 connected readiness |
| `kernel/src/net/socket/ip/datagram/unbound.rs` | 修改 | UDP 通配绑定与跨接口内部 Socket 创建 |
| `kernel/src/net/socket/ip/datagram/bound.rs` | 修改 | UDP 多接口发送选路、接收队列及事件汇聚 |
| `kernel/libs/aster-bigtcp/src/iface/port.rs` | 修改 | 跨接口端口占用和 `SO_REUSEADDR` 语义 |
| `kernel/libs/aster-bigtcp/src/socket/bound/tcp_listen.rs` | 修改 | 多 Listener 连接接收支持 |
| `kernel/libs/aster-bigtcp/src/socket/unbound.rs` | 修改 | 调整 TCP/UDP 默认 buffer |
| `test/initramfs/src/regression/network/inaddr_any.c` | 新增 | 多网卡 TCP/UDP 通配收发、冲突回滚、选路和失败重连测试 |
| `test/initramfs/src/regression/network/getsockname_any.c` | 新增 | `getsockname()` 通配端点测试 |
| `test/initramfs/src/regression/network/listen_autobind.c` | 新增 | 未绑定 TCP socket 直接 `listen()` 测试 |
| `test/initramfs/src/regression/network/localhost_loopback.c` | 新增 | TCP/UDP loopback 测试 |
| `test/initramfs/src/regression/network/tcp_accept_model.c` | 新增 | listener 顺序 accept 测试 |
| `test/initramfs/src/regression/network/socket_readiness.c` | 新增 | `poll/select/epoll` readiness 测试 |
| `test/initramfs/src/regression/network/tcp_reuseaddr.c` | 新增 | `SO_REUSEADDR` 服务快速重启测试 |
| `test/initramfs/src/regression/network/socket_buffer_defaults.c` | 新增 | 默认 socket buffer 测试 |
| `test/initramfs/src/regression/network/ipv6_any.c` | 新增 | TCP/UDP IPv6 当前边界与 IPv6 Raw Socket 测试 |
| `test/initramfs/src/regression/network/linux_socket_compat_common.c` | 新增 | Ubuntu / 修复前 Asterinas / 修复后 Asterinas 三方共同语义对照测试 |
| `test/initramfs/src/regression/network/linux_socket_compat.c` | 新增 | Asterinas 聚合兼容测试 |
| `test/initramfs/src/benchmark/flask_socket_demo/` | 新增 | Flask 单进程双网卡生命周期验证与九项可视化演示 |
| `scripts/watch-flask-pcap-evidence.py` | 新增 | 从两张 QEMU 网卡的 PCAP 中独立提取双路径证据 |
| `scripts/test-network-compat.sh` | 新增 | 指标二及网络兼容测试编译、kernel 构建、Flask demo 入口 |
| `scripts/compare-linux-socket-compat.sh` | 新增 | Ubuntu / 原始 Asterinas / 当前 Asterinas 三方对比脚本 |

### 技术指标三：Netfilter / iptables / NAT

| 路径 | 类型 | 说明 |
|---|---|---|
| `kernel/libs/aster-bigtcp/src/netfilter/hook.rs` | 新增 | 定义五个 Hook 点、verdict 与 IPv4 packet context |
| `kernel/libs/aster-bigtcp/src/netfilter/rule.rs` | 新增 | 定义规则、match 条件、target 和 counters |
| `kernel/libs/aster-bigtcp/src/netfilter/chain.rs` | 新增 | 组织内置链和默认策略 |
| `kernel/libs/aster-bigtcp/src/netfilter/table.rs` | 新增 | IPv4 filter/nat、有限 conntrack、SNAT/DNAT/MASQUERADE 与反向转换 |
| `kernel/libs/aster-bigtcp/src/netfilter/ipv6.rs` | 新增 | IPv6 Filter Hook、规则、策略和计数器 |
| `kernel/libs/aster-bigtcp/src/netfilter/ipv6_nat.rs` | 新增 | 有界 IPv6 SNAT/DNAT/MASQUERADE 与状态表 |
| `kernel/libs/aster-bigtcp/src/forwarding.rs` | 新增 | IPv4/IPv6 跨接口转发 packet 表示与地址改写 |
| `kernel/libs/aster-bigtcp/src/iface/poll.rs` | 修改 | IPv4/IPv6 Hook、转发队列及 NAT 数据路径 |
| `kernel/libs/aster-bigtcp/src/iface/phy/ether.rs` | 修改 | 以太网入口过滤、IPv6/NDP、转发与反向 NAT |
| `kernel/src/net/router.rs` | 修改 | 双网卡 IPv4/IPv6 转发控制与路由选择 |
| `kernel/src/fs/fs_impls/procfs/netfilter_rules.rs` | 新增 | iptables/ip6tables 兼容命令解析与 `/proc/netfilter_rules` 控制面 |
| `kernel/src/fs/fs_impls/procfs/mod.rs` | 修改 | 注册 `/proc/netfilter_rules` |
| `test/initramfs/src/regression/network/netfilter_rules.c` | 新增 | 规则生命周期、链策略、conntrack、NAT 数据路径和演示轨迹测试 |
| `test/initramfs/src/regression/network/netfilter_demo_step.c` | 新增 | 分步规则、连接跟踪与 NAT 场景演示 |
| `test/initramfs/src/regression/network/iptables.c` | 新增 | 最小用户态 iptables shim |

### 通用测试入口与文档

| 路径 | 类型 | 说明 |
|---|---|---|
| `test/initramfs/src/regression/network/run_test.sh` | 修改 | 接入 raw socket、socket compat、netfilter/iptables 等网络回归测试 |
| `docs/` | 新增 | 技术文档、进度汇报 PPT/PDF 和测试结果材料 |
| `scripts/test-network-compat.sh` | 新增 | 网络兼容测试编译、内核构建与 Flask demo 入口 |
| `scripts/compare-linux-socket-compat.sh` | 新增 | Ubuntu、原始 Asterinas 与当前 Asterinas 三方语义对照 |

## 测试与演示命令

本节按录屏和现场演示顺序组织命令，目标是可以从上到下线性复制运行。命令位置分为三类：宿主机、官方 Podman 编译环境、Asterinas guest。

### 1. 进入官方编译环境

在宿主机项目根目录执行：

```bash
sudo podman run --rm -it --privileged \
  --network=host \
  -v /dev:/dev \
  -v "$(pwd):/root/asterinas" \
  docker.io/asterinas/asterinas:0.18.0-20260603
```

进入容器后切换到项目目录：

```bash
cd /root/asterinas
```

### 2. 构建内核与完整回归测试

进入官方 Podman 编译环境后，先构建内核：

```bash
make kernel
```

随后运行完整 regression，并把日志保存下来，后续三个指标都从这份日志中截取关键结果：

```bash
AUTO_TEST=regression make run_kernel 2>&1 | tee target/regression-network.log
```

最终看到：

```text
All test in /test/network passed.
All regression tests passed.
```

### 3. 指标一：IPv4/IPv6 Raw Socket 与 ping

先从完整 regression 日志中观察 raw socket 与 ping 相关测试项：

```bash
grep -E "icmp_raw_socket|ipv6_any|create_multi_protocol_raw_sockets|send_loopback_echo_request|send_hdrincl_loopback_echo_request|ipv6_raw_loopback_echo_and_options|raw_local_error_queue|nonblocking_empty_receive|ping_loopback" \
  target/regression-network.log
```

重点结果包括：

```text
create_icmp_raw_socket
create_multi_protocol_raw_sockets
send_loopback_echo_request
send_hdrincl_loopback_echo_request
ipv6_raw_loopback_echo_and_options
ipv6_raw_hdrincl_custom_protocol
ipv6_raw_local_error_queue
nonblocking_empty_receive
test_ping_loopback summary: raw socket ping command passed
```

上述 `PASS` 表示 Asterinas 已支持 IPv4/IPv6 Raw Socket 创建、多协议分发、ICMP/ICMPv6 Echo、`IP_HDRINCL` / `IPV6_HDRINCL`、本地错误队列、非阻塞空读与命令级 `ping` 验证。路由相关回归还会检查 Raw Socket 根据目标地址选择出口，而不是固定使用默认接口。

如果需要在 NixOS guest 中手动展示 `iputils ping`，可使用显式 loopback 源地址触发稳定的 raw ICMP 路径：

```bash
ping -c 1 -W 1 -I 127.0.0.1 127.0.0.1
```

看到 `1 packets transmitted, 1 received, 0% packet loss`。

IPv6 loopback 可使用：

```bash
ping -6 -c 1 -W 1 ::1
```

### 4. 指标二：Linux Socket 兼容

先从完整 regression 日志中观察指标二单点回归和聚合回归：

```bash
grep -E "inaddr_any|getsockname_any|listen_autobind|localhost_loopback|tcp_accept_model|socket_readiness|tcp_reuseaddr|linux_socket_compat" \
  target/regression-network.log
```

重点测试项包括：

```text
inaddr_any
getsockname_any
listen_autobind
localhost_loopback
tcp_accept_model
socket_readiness
tcp_reuseaddr
linux_socket_compat
```

上述 `PASS` 表示 `0.0.0.0` 通配监听、`getsockname()`、未绑定 `listen()`、loopback、顺序 `accept()`、readiness、`SO_REUSEADDR` 和聚合服务路径均已通过回归测试。

然后在宿主机项目根目录运行 Ubuntu / 原始 Asterinas / 当前 Asterinas 三方共同语义对比：

```bash
scripts/compare-linux-socket-compat.sh all
```

对比结果：

| 目标 | 结果 | 通过 | 失败 |
|---|---:|---:|---:|
| Ubuntu 24.04 | PASS | 131 | 0 |
| 原始 Asterinas | FAIL | 112 | 19 |
| 当前 Asterinas | PASS | 131 | 0 |

该结果表示同一套 Linux socket 共同语义测试在 Ubuntu 上通过、在原始 Asterinas 上失败、在当前 Asterinas 上通过，可以直接体现兼容修复效果。

自动运行 Flask 双网卡生命周期测试：

```bash
scripts/test-network-compat.sh flask-demo
```

该入口使用 `MULTI_NET=on` 启动两张 VirtIO 网卡。`run.sh` 让同一个 Flask 进程绑定 `0.0.0.0`，分别通过 loopback、eth0 和 eth1 检查 health、通配端点、请求响应、64 KiB 响应和 accepted Socket 本地地址；随后关闭服务、立即在同一端口重启并重复探测。完整双网卡运行应输出：

```text
flask_socket_demo summary: 32 tests passed, 0 tests failed
flask_socket_demo: indicator 2 lifecycle completed
```

最后构建包含 Python、Flask 和 demo 源码的 NixOS 镜像：

```bash
make nixos
```

镜像位置：

```text
target/nixos/asterinas.img
```

宿主机运行 QEMU，挂载两张 VirtIO 网卡，并分别把两条网络路径上的 guest 8080 端口映射到宿主机 18080 和 18081：

```bash
sudo qemu-system-x86_64 \
  -enable-kvm \
  -cpu host \
  -m 8G \
  -bios /usr/share/edk2/x64/OVMF.4m.fd \
  -drive if=none,format=raw,id=x0,file="$PWD/target/nixos/asterinas.img" \
  -device virtio-blk-pci,drive=x0,disable-legacy=on,disable-modern=off \
  -device virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off \
  -netdev user,id=net0,net=10.0.2.0/24,dhcpstart=10.0.2.15,hostfwd=tcp:127.0.0.1:18080-:8080 \
  -object filter-dump,id=flask_net0_dump,netdev=net0,file="$PWD/target/flask-net0.pcap" \
  -device virtio-net-pci,netdev=net1,disable-legacy=on,disable-modern=off \
  -netdev user,id=net1,net=10.0.3.0/24,dhcpstart=10.0.3.15,hostfwd=tcp:127.0.0.1:18081-:8080 \
  -object filter-dump,id=flask_net1_dump,netdev=net1,file="$PWD/target/flask-net1.pcap" \
  -chardev stdio,id=mux,mux=on \
  -device virtio-serial-pci \
  -device virtconsole,chardev=mux \
  -serial chardev:mux \
  -monitor chardev:mux \
  -snapshot \
  -nographic
```

在 Asterinas guest 中启动 Flask 现场验收服务：

```bash
/benchmark/flask_socket_demo/ui.sh
```

宿主机浏览器可以从任一网卡对应入口访问：

```text
http://127.0.0.1:18080
http://127.0.0.1:18081
```

页面提供九个可自由选择、可重复执行的验证点，不再一键批量运行，也不要求按固定顺序操作。每次点击只检查一个兼容点，网页立即展示该项的期望值和实测值。第七项双入口交叉证明需要先分别执行 `18080 → eth0` 和 `18081 → eth1`，其余项目彼此独立。

九步依次覆盖：`INADDR_ANY` 通配监听、未绑定 `listen()`、`SO_REUSEADDR`、loopback TCP、浏览器 `18080 → eth0`、浏览器 `18081 → eth1`、双入口交叉证明、UDP 通配收发和同端口服务重启。两条浏览器路径使用独立请求和唯一令牌，分别证明 accepted socket 为 `10.0.2.15:8080` 与 `10.0.3.15:8080`；交叉步骤再证明两者命中相同 Flask PID 和同一个 `0.0.0.0:8080` listener。

Flask 的 `STEP_EVIDENCE` 只作为被测应用的解释性日志，不作为双网卡路径的最终证明。QEMU 命令中的两个 `filter-dump` 会由虚拟机外部观察者分别生成 `flask-net0.pcap` 和 `flask-net1.pcap`。在宿主机另开终端运行独立监视器：

```bash
python3 scripts/watch-flask-pcap-evidence.py \
  target/flask-net0.pcap target/flask-net1.pcap
```

点击两个浏览器入口项目时，监视器应分别输出：

```text
QEMU_PCAP_EVIDENCE source=net0/eth0 ... dst=10.0.2.15:8080 request="GET /api/demo/path-proof?..."
QEMU_PCAP_EVIDENCE source=net1/eth1 ... dst=10.0.3.15:8080 request="GET /api/demo/path-proof?..."
```

这些记录直接解析 QEMU 在两张虚拟网卡上捕获的原始 Ethernet/IPv4/TCP 帧，不依赖 Flask 对本地地址的自我报告。PCAP 文件还可以交给 Wireshark 或 `tcpdump -nn -r` 独立复核。对于 `listen()`、`SO_REUSEADDR` 等纯 syscall 语义，页面用于现场演示，最终证据仍以独立 C regression 测试为准。

端口冲突原子回滚、连接拒绝后重连和 Linux 131 项共同语义对比仍作为离线 regression 证据，页面会明确标注证据边界，不把历史结果伪装成现场执行结果。

### 5. 指标三：Netfilter、连接跟踪与 NAT

先从完整 regression 日志中观察 netfilter / iptables 相关测试项：

```bash
grep -E "netfilter|iptables|ip6tables|conntrack|nat|test_match_netfilter|test_run_userspace_iptables" \
  target/regression-network.log
```

重点测试项包括：

```text
test_match_netfilter_accept_drop_targets
test_match_netfilter_iptables_command_compat
test_run_userspace_iptables_shim
test_run_userspace_iptables_tcp_udp_port_matches
test_run_userspace_iptables_input_forward_filter_chains
test_run_userspace_iptables_conntrack_state_matches
test_run_userspace_iptables_nat_control_plane
test_run_userspace_iptables_nat_rule_lifecycle
test_run_userspace_iptables_nat_postrouting_data_path
```

上述 `PASS` 表示规则控制面、ACCEPT/DROP、INPUT/OUTPUT/FORWARD、iptables shim、TCP/UDP 端口匹配、NEW/ESTABLISHED 连接跟踪以及 SNAT/DNAT/MASQUERADE 规则与数据路径均已进入回归测试。IPv6 过滤、转发和 NAT66 通过 `ip6tables` 控制面、双网卡 IPv6 拓扑及对应场景测试验证。

在已经启动 Flask 服务的 Asterinas guest 中，先清空 OUTPUT 规则并查看规则状态：

```bash
echo "iptables -F OUTPUT" > /proc/netfilter_rules
cat /proc/netfilter_rules
```

宿主机确认 Web 服务可以访问：

```bash
curl -v http://127.0.0.1:18080
```

此时服务可访问，表示没有 DROP 规则影响 8080 端口响应。

然后在 guest 中添加规则，阻断 Flask 从 8080 端口发出的 TCP 响应，并查看规则日志：

```bash
echo "iptables -A OUTPUT -p tcp --sport 8080 -j DROP" > /proc/netfilter_rules
cat /proc/netfilter_rules
```

宿主机再次访问同一地址，此时连接会超时或无法拿到 HTTP 响应：

```bash
curl -v --max-time 3 http://127.0.0.1:18080
```

此时超时或无法拿到 HTTP 响应，表示 netfilter 规则已经作用到真实服务的数据路径。

恢复 Web 访问时，在 guest 中清空 OUTPUT 规则并再次查看规则状态：

```bash
echo "iptables -F OUTPUT" > /proc/netfilter_rules
cat /proc/netfilter_rules
```

宿主机再次确认服务恢复：

```bash
curl -v http://127.0.0.1:18080
```

服务重新可访问，表示规则清空后数据路径恢复正常。

## 创新贡献

本项目的主要贡献包括：

1. 在 Asterinas 中补齐 IPv4/IPv6 Raw Socket 路径，覆盖 ICMP/ICMPv6、多协议分发、HDRINCL、错误队列、事件通知与路由感知发送，使 `ping`、`ping -6` 和协议级网络工具具备运行基础。

2. 将 Linux Socket ABI 语义和 smoltcp 的单接口 Socket 模型解耦：上层维持一个通配用户态 Socket，下层建立并管理跨接口的实际 Socket 集合。

3. 系统化修复 Web 服务完整生命周期：通配绑定、跨接口原子端口预留、`getsockname()`、隐式 `listen()`、多网卡 TCP/UDP 收发、事件汇聚、非阻塞语义、资源释放和 `SO_REUSEADDR` 快速重启。

4. 构建 Ubuntu / 原始 Asterinas / 当前 Asterinas 三方共同语义对照测试，用同一份 C 测试程序证明“Linux 通过、修复前失败、修复后通过”。

5. 增加真实 Flask 双网卡生命周期测试与九项可视化演示，通过相同 PID、相同通配 Listener、不同 accepted 地址和独立 QEMU PCAP 证明一个服务覆盖多条网络路径。

6. 在 Asterinas 的 IPv4/IPv6 本地和转发路径中实现 Netfilter Hook 与规则执行框架，形成可扩展的内核包处理基础。

7. 提供 iptables/ip6tables 兼容控制面、规则计数器、有限连接跟踪，以及 IPv4/IPv6 SNAT、MASQUERADE、DNAT 和返回路径反向转换。

8. 对实现边界保持显式说明：指标二 TCP/UDP 服务语义仍以 IPv4 为主；Raw Socket 选项、Linux backlog 双队列、`SO_REUSEPORT`、buffer autotuning、完整 conntrack 和完整 iptables/nftables ABI 仍未覆盖。

## 鸣谢

感谢全国大学生操作系统比赛提供本项目选题和实践平台。

感谢星绽操作系统和 Asterinas 社区提供 Rust OS 基础代码、构建工具和文档资料。

感谢 smoltcp 项目提供轻量级 Rust TCP/IP 协议栈实现。

感谢吉林大学、指导教师宋姗姗和郭佳妮老师在项目选题、技术路线和文档整理方面给予的指导。

感谢团队成员在 raw socket、Linux socket 语义兼容、netfilter/iptables 子集实现、测试验证、报告撰写和演示材料整理中的协作。

# Rust OS 网络栈功能扩展与 Linux 兼容性增强

队伍名称：88博弈  
所属赛题：Proj12  
所属高校：吉林大学  
项目成员：俞俊升、童旭光、孙威  
指导教师：宋姗姗、郭佳妮

## 项目背景

星绽操作系统（Asterinas）是一个以 Rust 为主要实现语言、面向 Linux ABI 兼容目标的操作系统内核。其网络能力基于 smoltcp 和内部 `aster-bigtcp` 抽象构建，具有结构清晰、资源可控和安全性较强等特点。

但 smoltcp 本身面向轻量级、嵌入式和 no_std 场景，并不完整复刻 Linux 网络语义。因此，在运行常见 Linux 网络程序时，Asterinas 原有网络栈仍存在一些能力缺口：

- 缺少 IP raw socket，导致 `ping` 等依赖 ICMP raw socket 的工具无法正常运行；
- `0.0.0.0` / `INADDR_ANY`、`listen()`、`getsockname()`、`SO_REUSEADDR` 等 socket 语义与 Linux 不一致，影响 Flask、Python HTTP server、Redis 等服务启动和运行；
- 缺少类似 Linux netfilter/iptables 的包处理框架，难以支撑基础包过滤与 NAT 场景。

本项目围绕“Rust OS 网络栈功能扩展与 Linux 兼容性增强”目标，从协议访问能力、socket 接口语义和内核级包处理框架三个层次对 Asterinas 网络栈进行扩展。

## 功能

### 技术指标一：Raw Socket 支持与 ping 可用性

本项目实现了 IPv4 raw ICMP socket 的最小可用子集，使 `ping` 等基础网络诊断工具具备运行条件。

主要能力包括：

- 支持 `AF_INET / SOCK_RAW / IPPROTO_ICMP` socket 创建；
- 创建 raw socket 时进行 `CAP_NET_RAW` 权限检查；
- 接收方向向用户态返回完整 IPv4 packet；
- 支持 ICMP Echo Request / Echo Reply 收发闭环；
- 支持 loopback 场景下 `ping` 命令级验证；
- 支持 `IP_HDRINCL` 基础兼容路径；
- 支持 raw socket 的非阻塞读写和 `poll` readiness；
- 对 raw packet 接收/发送队列设置 packet 数量和字节数上限，避免无界资源占用。

### 技术指标二：smoltcp 与 Linux 网络接口语义差异修复

本项目以 Flask、Python HTTP server、Redis 等常见服务的运行路径为目标，修复 Asterinas 与 Linux 在 IPv4 socket 服务端语义上的关键差异。

主要能力包括：

- 支持 TCP/UDP `bind(0.0.0.0)` 作为 Linux `INADDR_ANY` 通配绑定；
- 外部连接发往 guest 实际 IPv4 地址时可以命中 `0.0.0.0` listener；
- `getsockname()` 保留用户可见端点，例如 `0.0.0.0:<actual-port>`；
- 支持未显式 `bind()` 的 TCP socket 直接 `listen()`，自动绑定到 `INADDR_ANY:ephemeral`；
- 保持 `127.0.0.1` loopback TCP/UDP 路径正确；
- 支持同一 listener 顺序 `accept()` 多个连接；
- 补齐 TCP/UDP `poll/select/epoll` readiness 的最小服务语义；
- 支持 `SO_REUSEADDR` 下服务关闭后同端口快速重启；
- 提升默认 socket buffer，覆盖普通 HTTP 响应首批写入；
- 对 IPv4-only 路径中的 `AF_INET6` 明确返回 `EAFNOSUPPORT`，避免伪装支持 IPv6。

### 技术指标三：netfilter 框架与 iptables 最小可用子集

本项目实现了面向 Asterinas IPv4 数据路径的 netfilter/iptables 最小可用子集，为包过滤和 NAT 扩展提供基础框架。

主要能力包括：

- 在 IPv4 ingress/egress 路径接入 netfilter hook；
- 定义 `PREROUTING`、`LOCAL_IN`、`LOCAL_OUT`、`POSTROUTING` 等 hook 点；
- 支持 filter 表 `OUTPUT` 链；
- 支持规则有序匹配、first-match 语义和默认 `ACCEPT` 策略；
- 支持 ICMP/TCP/UDP 协议匹配、IPv4 地址匹配、端口匹配和 ICMP identifier 匹配；
- 支持 `ACCEPT` / `DROP` target；
- 支持规则 packet/byte counters；
- 提供 `/proc/netfilter_rules` 控制面；
- 提供最小用户态 `iptables` shim，支持常见 `-A/-D/-F/-Z/-L` 形式命令；
- 支持 nat 表控制面和部分 `POSTROUTING` SNAT/MASQUERADE 改写辅助能力。

## 代码结构

以下只列出本项目开发或修改的关键位置，未列出的目录主要为 Asterinas 原有代码。

### 技术指标一：Raw Socket

| 路径 | 类型 | 说明 |
|---|---|---|
| `kernel/src/syscall/socket.rs` | 修改 | 增加 IPv4 raw ICMP socket 创建分发路径 |
| `kernel/src/net/socket/ip/raw.rs` | 新增 | RawSocket 主体实现，负责权限检查、sendmsg、recvmsg、poll、IP_HDRINCL |
| `kernel/src/net/socket/ip/raw_observer.rs` | 新增 | raw socket readiness 观察器 |
| `kernel/src/net/socket/ip/options.rs` | 修改 | 增加 raw socket IP option 集合，支持 `IP_HDRINCL` |
| `kernel/src/net/socket/ip/mod.rs` | 修改 | 注册并导出 RawSocket |
| `kernel/src/net/iface/mod.rs` | 修改 | 增加 raw socket 相关类型别名 |
| `kernel/libs/aster-bigtcp/src/socket/raw_ip.rs` | 新增 | RawIpSocket 接收/发送队列和资源边界控制 |
| `kernel/libs/aster-bigtcp/src/socket/mod.rs` | 修改 | 导出 raw IP socket 类型 |
| `kernel/libs/aster-bigtcp/src/socket_table.rs` | 修改 | 增加按 IP protocol 匹配的 raw socket 注册表 |
| `kernel/libs/aster-bigtcp/src/iface/common.rs` | 修改 | 网络接口生命周期中注册 raw socket |
| `kernel/libs/aster-bigtcp/src/iface/poll.rs` | 修改 | IPv4 ingress raw 投递、本地 ICMP 注入、raw egress、Echo Reply |
| `test/initramfs/src/regression/network/icmp_raw_socket.c` | 新增 | raw socket 创建、接收、发送、IP_HDRINCL 回归测试 |
| `test/initramfs/src/regression/network/ping_loopback.sh` | 新增 | `ping` 命令级回归测试 |

### 技术指标二：Linux Socket 语义兼容

| 路径 | 类型 | 说明 |
|---|---|---|
| `kernel/src/net/socket/ip/common.rs` | 修改 | 处理 `INADDR_ANY`，选择默认服务接口 |
| `kernel/src/net/socket/ip/addr.rs` | 修改 | 分离内部绑定端点和用户可见端点 |
| `kernel/src/net/socket/ip/stream/init.rs` | 修改 | 支持未绑定 TCP socket 直接 `listen()` 自动绑定 |
| `kernel/src/net/socket/ip/stream/listen.rs` | 修改 | listener `accept()` 与 readiness 行为适配 |
| `kernel/src/net/socket/ip/stream/connected.rs` | 修改 | connected TCP socket readiness 适配 |
| `kernel/src/net/socket/ip/datagram/unbound.rs` | 修改 | UDP bind 与用户可见端点适配 |
| `kernel/src/net/socket/ip/datagram/bound.rs` | 修改 | UDP bound socket readiness 与端点适配 |
| `kernel/libs/aster-bigtcp/src/iface/port.rs` | 修改 | `SO_REUSEADDR` 端口复用语义适配 |
| `kernel/libs/aster-bigtcp/src/socket/unbound.rs` | 修改 | 调整 TCP/UDP 默认 buffer |
| `test/initramfs/src/regression/network/inaddr_any.c` | 新增 | `0.0.0.0` TCP/UDP 通配绑定测试 |
| `test/initramfs/src/regression/network/getsockname_any.c` | 新增 | `getsockname()` 通配端点测试 |
| `test/initramfs/src/regression/network/listen_autobind.c` | 新增 | 未绑定 TCP socket 直接 `listen()` 测试 |
| `test/initramfs/src/regression/network/localhost_loopback.c` | 新增 | TCP/UDP loopback 测试 |
| `test/initramfs/src/regression/network/tcp_accept_model.c` | 新增 | listener 顺序 accept 测试 |
| `test/initramfs/src/regression/network/socket_readiness.c` | 新增 | `poll/select/epoll` readiness 测试 |
| `test/initramfs/src/regression/network/tcp_reuseaddr.c` | 新增 | `SO_REUSEADDR` 服务快速重启测试 |
| `test/initramfs/src/regression/network/socket_buffer_defaults.c` | 新增 | 默认 socket buffer 测试 |
| `test/initramfs/src/regression/network/ipv6_any.c` | 新增 | IPv6 unsupported 边界测试 |
| `test/initramfs/src/regression/network/linux_socket_compat_common.c` | 新增 | Ubuntu / 修复前 Asterinas / 修复后 Asterinas 三方共同语义对照测试 |
| `test/initramfs/src/regression/network/linux_socket_compat.c` | 新增 | Asterinas 聚合兼容测试 |
| `test/initramfs/src/benchmark/flask_socket_demo/` | 新增 | Flask 真实服务验证与可视化演示 |
| `scripts/test-network-compat.sh` | 新增 | 指标二及网络兼容测试编译、kernel 构建、Flask demo 入口 |
| `scripts/compare-linux-socket-compat.sh` | 新增 | Ubuntu / 原始 Asterinas / 当前 Asterinas 三方对比脚本 |

### 技术指标三：netfilter / iptables

| 路径 | 类型 | 说明 |
|---|---|---|
| `kernel/libs/aster-bigtcp/src/netfilter/hook.rs` | 新增 | 定义 hook 点、verdict、IPv4 packet context |
| `kernel/libs/aster-bigtcp/src/netfilter/rule.rs` | 新增 | 定义规则、match 条件、target 和 counters |
| `kernel/libs/aster-bigtcp/src/netfilter/chain.rs` | 新增 | 组织内置链和默认策略 |
| `kernel/libs/aster-bigtcp/src/netfilter/table.rs` | 新增 | filter/nat 表规则集合与执行逻辑 |
| `kernel/libs/aster-bigtcp/src/netfilter/mod.rs` | 新增 | netfilter 模块导出入口 |
| `kernel/libs/aster-bigtcp/src/iface/poll.rs` | 修改 | 在 IPv4 收发路径调用 netfilter hook，并接入 POSTROUTING NAT 辅助改写 |
| `kernel/src/fs/fs_impls/procfs/netfilter_rules.rs` | 新增 | `/proc/netfilter_rules` 控制面 |
| `kernel/src/fs/fs_impls/procfs/mod.rs` | 修改 | 注册 `/proc/netfilter_rules` |
| `test/initramfs/src/regression/network/netfilter_rules.c` | 新增 | netfilter 规则读写、ACCEPT/DROP、计数器、NAT smoke 测试 |
| `test/initramfs/src/regression/network/iptables.c` | 新增 | 最小用户态 iptables shim |

### 通用测试入口与文档

| 路径 | 类型 | 说明 |
|---|---|---|
| `test/initramfs/src/regression/network/run_test.sh` | 修改 | 接入 raw socket、socket compat、netfilter/iptables 等网络回归测试 |
| `doc/` | 新增 | 指标二报告、兼容点说明、测试结果与演示材料 |
| `stage-records/` | 新增 | 阶段记录、测试证据和日志摘要 |
| `tools/raw_socket/` | 新增 | raw socket 阶段测试和证据采集脚本 |

## 操作命令

### 进入官方编译环境

```bash
sudo podman run --rm -it --privileged \
  --network=host \
  -v /dev:/dev \
  -v "$(pwd):/root/asterinas" \
  docker.io/asterinas/asterinas:0.18.0-20260603
```

进入容器后：

```bash
cd /root/asterinas
```

### 构建内核

```bash
make kernel
```

### 运行完整 regression

```bash
AUTO_TEST=regression make run_kernel
```

期望结果：

```text
All regression tests passed.
```

### 运行指标一 raw socket / ping 相关测试

raw socket 测试已经接入 network regression，可通过完整 regression 运行：

```bash
AUTO_TEST=regression make run_kernel
```

重点关注日志中的：

```text
test_create_icmp_raw_socket
test_receive_local_port_unreachable
test_send_loopback_echo_request
test_send_hdrincl_loopback_echo_request
test_nonblocking_empty_receive
test_ping_loopback summary: raw socket ping command passed
```

### 运行指标二网络兼容测试

快速编译检查：

```bash
scripts/test-network-compat.sh compile
```

在官方 podman 环境中编译检查：

```bash
scripts/test-network-compat.sh podman-compile
```

构建内核并检查指标二相关测试：

```bash
scripts/test-network-compat.sh kernel
```

运行 Ubuntu / 原始 Asterinas / 当前 Asterinas 三方共同语义对比：

```bash
scripts/compare-linux-socket-compat.sh all
```

也可以分别运行：

```bash
scripts/compare-linux-socket-compat.sh ubuntu
scripts/compare-linux-socket-compat.sh original
scripts/compare-linux-socket-compat.sh current
```

期望对比结果：

| 目标 | 结果 | 通过 | 失败 |
|---|---:|---:|---:|
| Ubuntu 24.04 | PASS | 131 | 0 |
| 原始 Asterinas | FAIL | 112 | 19 |
| 当前 Asterinas | PASS | 131 | 0 |

### 运行 Flask 服务测试

自动化运行 Flask demo：

```bash
scripts/test-network-compat.sh flask-demo
```

期望日志：

```text
flask_socket_demo summary: 8 tests passed, 0 tests failed
flask_socket_demo: service startup and request handling passed
```

手动演示方式：

```bash
make nixos
```

镜像位置：

```text
target/nixos/asterinas.img
```

宿主机运行 QEMU：

```bash
sudo qemu-system-x86_64 \
  -enable-kvm \
  -cpu host \
  -m 8G \
  -bios /usr/share/edk2/x64/OVMF.4m.fd \
  -drive if=none,format=raw,id=x0,file="$PWD/target/nixos/asterinas.img" \
  -device virtio-blk-pci,drive=x0,disable-legacy=on,disable-modern=off \
  -device virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off \
  -netdev user,id=net0,hostfwd=tcp:0.0.0.0:18080-:8080 \
  -chardev stdio,id=mux,mux=on \
  -device virtio-serial-pci \
  -device virtconsole,chardev=mux \
  -serial chardev:mux \
  -monitor chardev:mux \
  -nographic
```

guest 中启动 Flask：

```bash
/benchmark/bin/python3 /benchmark/flask_socket_demo/app.py --host 0.0.0.0 --port 8080
```

宿主机浏览器访问：

```text
http://127.0.0.1:18080
```

### 运行指标三 netfilter / iptables 测试

netfilter 测试已经接入 network regression：

```bash
AUTO_TEST=regression make run_kernel
```

重点关注日志中的：

```text
test_match_netfilter_accept_drop_targets
test_match_netfilter_iptables_command_compat
test_run_userspace_iptables_shim
test_run_userspace_iptables_tcp_udp_port_matches
test_run_userspace_iptables_nat_control_plane
test_run_userspace_iptables_nat_postrouting_data_path
All test in /test/network passed.
All regression tests passed.
```

也可以在 NixOS guest 中手动演示 netfilter 规则对真实服务流量的影响。先后台启动 Flask 服务：

```bash
/benchmark/bin/python3 /benchmark/flask_socket_demo/app.py --host 0.0.0.0 --port 8080 &
```

宿主机通过 QEMU `hostfwd` 访问服务：

```bash
curl -v http://127.0.0.1:18080
```

在 guest 中安装 OUTPUT 过滤规则，阻断 Flask 从 8080 端口发出的 TCP 响应：

```bash
echo "iptables -F OUTPUT" > /proc/netfilter_rules
echo "iptables -A OUTPUT -p tcp --sport 8080 -j DROP" > /proc/netfilter_rules
cat /proc/netfilter_rules
```

此时宿主机再次访问同一地址，连接会超时或无法拿到 HTTP 响应，用于展示规则已经作用到服务数据路径：

```bash
curl -v --max-time 3 http://127.0.0.1:18080
```

恢复 Web 访问时清空 OUTPUT 规则：

```bash
echo "iptables -F OUTPUT" > /proc/netfilter_rules
```

如果需要恢复项目默认演示规则，可以再加回默认 ICMP 规则：

```bash
echo "iptables -A OUTPUT -p icmp --icmp-type echo-request --icmp-id 0x0828 -j DROP" > /proc/netfilter_rules
```

## 创新贡献

本项目的主要贡献包括：

1. 在 Asterinas 中补齐 IPv4 raw ICMP socket 最小可用路径，使 `ping` 等基础网络诊断工具具备运行条件。

2. 将 Linux socket ABI 语义和 smoltcp 内部网络模型解耦：上层保持 Linux 用户态可见行为，下层仍按具体 iface 和具体 IPv4 地址完成收发。

3. 系统化修复常见服务运行所需的 socket 语义，不只修复 `0.0.0.0`，还覆盖 `getsockname()`、未绑定 `listen()`、loopback、accept、readiness、`SO_REUSEADDR`、buffer 等完整服务生命周期。

4. 构建 Ubuntu / 原始 Asterinas / 当前 Asterinas 三方共同语义对照测试，用同一份 C 测试程序证明“Linux 通过、修复前失败、修复后通过”。

5. 增加真实 Flask 服务测试和可视化演示，证明修复后的网络栈可以支撑 Python Web 服务启动、监听、请求处理、大响应返回和同端口重启。

6. 在 Asterinas 的 IPv4 数据路径中实现 netfilter hook 与规则执行框架，形成可扩展的包处理基础。

7. 提供最小 iptables shim 和 `/proc/netfilter_rules` 控制面，使规则管理、过滤效果、计数器和 NAT smoke 能够被用户态测试直接验证。

8. 对未完整实现的能力明确边界，包括完整 IPv6、完整 Linux backlog 双队列、SO_REUSEPORT、TCP buffer autotuning、完整 conntrack、return-path NAT 和完整 Linux iptables ABI。

## 鸣谢

感谢全国大学生操作系统比赛提供本项目选题和实践平台。

感谢星绽操作系统和 Asterinas 社区提供 Rust OS 基础代码、构建工具和文档资料。

感谢 smoltcp 项目提供轻量级 Rust TCP/IP 协议栈实现。

感谢吉林大学、指导教师宋姗姗和郭佳妮老师在项目选题、技术路线和文档整理方面给予的指导。

感谢团队成员在 raw socket、Linux socket 语义兼容、netfilter/iptables 子集实现、测试验证、报告撰写和演示材料整理中的协作。

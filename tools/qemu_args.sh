#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

# This script is used to generate QEMU arguments for OSDK.
# Usage: `qemu_args.sh [scheme]`
#  - scheme: "normal", "test", "microvm" or "iommu";
# Other arguments are configured via environmental variables:
#  - OVMF: "on" or "off";
#  - BOOT_METHOD: "qemu-direct", "grub-rescue-iso" or "grub-qcow2";
#  - BOOT_PROTOCOL: "multiboot", "multiboot2", "linux-legacy32", "linux-efi-pe64" or "linux-efi-handover64";
#  - NETDEV：可取 "user"、"tap" 或 "router-tap"；
#  - MULTI_NET：设为 "on" 时挂载第二张用户模式网络（仅开发使用）；
#  - ROUTER_TAP0、ROUTER_TAP1：NETDEV=router-tap 时使用的宿主机 TAP 名称；
#  - VHOST: "off" or "on";
#  - VSOCK: "off" or "on";
#  - CONSOLE: "hvc0" to enable virtio console;
#  - SMP: number of CPUs;
#  - MEM: amount of memory, e.g. "8G";
#  - VNC_PORT: VNC port, default is "42".

OVMF=${OVMF:-"on"}
VHOST=${VHOST:-"off"}
VSOCK=${VSOCK:-"off"}
NETDEV=${NETDEV:-"user"}
MULTI_NET=${MULTI_NET:-"off"}
CONSOLE=${CONSOLE:-"hvc0"}
NETFILTER_DEMO_SOCKET=${NETFILTER_DEMO_SOCKET:-"stage-records/demo/netfilter-demo-step.sock"}
NETFILTER_DEMO_SERIAL_LOG=${NETFILTER_DEMO_SERIAL_LOG:-"stage-records/demo/netfilter-demo-step-serial.log"}

USED_HOSTFWD_PORTS=""

host_port_is_unavailable() {
    local port=$1

    case " $USED_HOSTFWD_PORTS " in
        *" $port "*) return 0 ;;
    esac

    if command -v ss >/dev/null 2>&1 &&
        ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
        return 0
    fi

    return 1
}

reserve_hostfwd_port() {
    local port=$1

    if host_port_is_unavailable "$port"; then
        echo "Host forwarding port $port is already reserved or listening." >&2
        exit 1
    fi
    USED_HOSTFWD_PORTS="$USED_HOSTFWD_PORTS $port"
}

choose_hostfwd_port() {
    local variable=$1
    local port

    while :; do
        port=$(shuf -i 1024-65535 -n 1)
        if ! host_port_is_unavailable "$port"; then
            USED_HOSTFWD_PORTS="$USED_HOSTFWD_PORTS $port"
            printf -v "$variable" '%s' "$port"
            return
        fi
    done
}

assign_hostfwd_port() {
    local variable=$1
    local override_name=$2
    local override_value=${!override_name:-}

    if [ -n "$override_value" ]; then
        if ! [[ "$override_value" =~ ^[0-9]+$ ]] ||
            [ "$override_value" -lt 1024 ] || [ "$override_value" -gt 65535 ]; then
            echo "$override_name must be a TCP port in the range 1024-65535" >&2
            exit 1
        fi
        reserve_hostfwd_port "$override_value"
        printf -v "$variable" '%s' "$override_value"
    else
        choose_hostfwd_port "$variable"
    fi
}

assign_hostfwd_port SSH_RAND_PORT SSH_PORT
assign_hostfwd_port NGINX_RAND_PORT NGINX_PORT
assign_hostfwd_port REDIS_RAND_PORT REDIS_PORT
assign_hostfwd_port IPERF_RAND_PORT IPERF_PORT
assign_hostfwd_port LMBENCH_TCP_LAT_RAND_PORT LMBENCH_TCP_LAT_PORT
assign_hostfwd_port LMBENCH_TCP_BW_RAND_PORT LMBENCH_TCP_BW_PORT
assign_hostfwd_port MEMCACHED_RAND_PORT MEMCACHED_PORT

# Optional QEMU arguments. Opt in them manually if needed.
# QEMU_OPT_ARG_DUMP_PACKETS="-object filter-dump,id=filter0,netdev=net01,file=virtio-net.pcap"

if [ "$NETDEV" = "user" ]; then
    echo "[$1] Forwarded QEMU guest port: $SSH_RAND_PORT->22; $NGINX_RAND_PORT->8080 $REDIS_RAND_PORT->6379 $IPERF_RAND_PORT->5201 $LMBENCH_TCP_LAT_RAND_PORT->31234 $LMBENCH_TCP_BW_RAND_PORT->31236 $MEMCACHED_RAND_PORT->11211" 1>&2
    NETDEV_ARGS="-netdev user,id=net01,hostfwd=tcp::$SSH_RAND_PORT-:22,hostfwd=tcp::$NGINX_RAND_PORT-:8080,hostfwd=tcp::$REDIS_RAND_PORT-:6379,hostfwd=tcp::$IPERF_RAND_PORT-:5201,hostfwd=tcp::$LMBENCH_TCP_LAT_RAND_PORT-:31234,hostfwd=tcp::$LMBENCH_TCP_BW_RAND_PORT-:31236,hostfwd=tcp::$MEMCACHED_RAND_PORT-:11211"
    VIRTIO_NET_FEATURES=",mrg_rxbuf=off,ctrl_rx=off,ctrl_rx_extra=off,ctrl_vlan=off,ctrl_vq=off,ctrl_guest_offloads=off,ctrl_mac_addr=off,event_idx=off,queue_reset=off,guest_announce=off,indirect_desc=off"
elif [ "$NETDEV" = "tap" ]; then
    THIS_SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
    QEMU_IFUP_SCRIPT_PATH=$THIS_SCRIPT_DIR/net/qemu-ifup.sh
    QEMU_IFDOWN_SCRIPT_PATH=$THIS_SCRIPT_DIR/net/qemu-ifdown.sh
    NETDEV_ARGS="-netdev tap,id=net01,script=$QEMU_IFUP_SCRIPT_PATH,downscript=$QEMU_IFDOWN_SCRIPT_PATH,vhost=$VHOST"
    VIRTIO_NET_FEATURES=",csum=off,guest_csum=off,ctrl_guest_offloads=off,guest_tso4=off,guest_tso6=off,guest_ecn=off,guest_ufo=off,host_tso4=off,host_tso6=off,host_ecn=off,host_ufo=off,mrg_rxbuf=off,ctrl_vq=off,ctrl_rx=off,ctrl_vlan=off,ctrl_rx_extra=off,guest_announce=off,ctrl_mac_addr=off,host_ufo=off,guest_uso4=off,guest_uso6=off,host_uso=off"
elif [ "$NETDEV" = "router-tap" ]; then
    if [ -z "$ROUTER_TAP0" ] || [ -z "$ROUTER_TAP1" ]; then
        echo "NETDEV=router-tap requires ROUTER_TAP0 and ROUTER_TAP1" 1>&2
        exit 1
    fi
    if [ "$1" = "tdx" ] || [ "$1" = "microvm" ]; then
        echo "NETDEV=router-tap currently supports the normal QEMU scheme only" 1>&2
        exit 1
    fi
    # TAP 生命周期由验收框架负责。不要让 QEMU 运行常规单 TAP ifup/down 脚本，
    # 否则这些端点会连接到宿主机默认网桥，而不是隔离的路由器网桥。
    NETDEV_ARGS="-netdev tap,id=net01,ifname=$ROUTER_TAP0,script=no,downscript=no,vhost=$VHOST -netdev tap,id=net02,ifname=$ROUTER_TAP1,script=no,downscript=no,vhost=$VHOST"
    VIRTIO_NET_FEATURES=",csum=off,guest_csum=off,ctrl_guest_offloads=off,guest_tso4=off,guest_tso6=off,guest_ecn=off,guest_ufo=off,host_tso4=off,host_tso6=off,host_ecn=off,host_ufo=off,mrg_rxbuf=off,ctrl_vq=off,ctrl_rx=off,ctrl_vlan=off,ctrl_rx_extra=off,guest_announce=off,ctrl_mac_addr=off,host_ufo=off,guest_uso4=off,guest_uso6=off,host_uso=off"
else 
    echo "Invalid netdev" 1>&2
    NETDEV_ARGS="-nic none"
fi

# 两个用户模式后端足以测试设备枚举和接口命名。它们不是端到端转发拓扑；
# 阶段 2 路由器验收测试使用由 TAP 支撑的隔离端点。
if [ "$MULTI_NET" = "on" ]; then
    if [ "$NETDEV" != "user" ]; then
        echo "MULTI_NET=on currently requires NETDEV=user" 1>&2
        exit 1
    fi
    if [ "$1" = "tdx" ] || [ "$1" = "microvm" ]; then
        echo "MULTI_NET=on currently supports the normal QEMU scheme only" 1>&2
        exit 1
    fi
    NETDEV_ARGS="$NETDEV_ARGS -netdev user,id=net02,net=10.0.3.0/24,dhcpstart=10.0.3.15"
fi

if [ "$AUTO_TEST" = "demo-step" ]; then
    # 交互式演示独占专用串口 Socket。宿主机 dashboard 向该 Socket 写入命令行
    #（next/reset/scenario <name>），同时 QEMU 在共享仓库路径中保存完整串口记录。
    mkdir -p "$(dirname "$NETFILTER_DEMO_SOCKET")" "$(dirname "$NETFILTER_DEMO_SERIAL_LOG")"
    rm -f "$NETFILTER_DEMO_SOCKET" "$NETFILTER_DEMO_SERIAL_LOG"
    if [ "$CONSOLE" = "hvc0" ]; then
        CONSOLE_ARGS="-chardev socket,id=demo_serial,path=$NETFILTER_DEMO_SOCKET,server=on,wait=off,logfile=$NETFILTER_DEMO_SERIAL_LOG -device virtconsole,chardev=demo_serial"
    else
        CONSOLE_ARGS="-chardev socket,id=demo_serial,path=$NETFILTER_DEMO_SOCKET,server=on,wait=off,logfile=$NETFILTER_DEMO_SERIAL_LOG -serial chardev:demo_serial"
    fi
elif [ "$CONSOLE" = "hvc0" ]; then
    # Kernel logs are printed to all consoles. Redirect serial output to a file to avoid duplicate logs.
    CONSOLE_ARGS="-device virtconsole,chardev=mux -serial file:qemu-serial.log"
else
    CONSOLE_ARGS="-serial chardev:mux"
fi

if [ "$1" = "tdx" ]; then
    TDX_OBJECT='{ "qom-type": "tdx-guest", "id": "tdx0", "sept-ve-disable": true, "quote-generation-socket": { "type": "vsock", "cid": "2", "port": "4050" } }'

    QEMU_ARGS="\
        -m ${MEM:-8G} \
        -smp ${SMP:-1} \
        -vga none \
        -nographic \
        -monitor pty \
        -nodefaults \
        -bios /root/ovmf/release/OVMF.fd \
        -cpu host,-kvm-steal-time,pmu=off \
        -machine q35,kernel-irqchip=split,confidential-guest-support=tdx0 \
        -object '$TDX_OBJECT' \
        -device virtio-net-pci,netdev=net01,disable-legacy=on,disable-modern=off$VIRTIO_NET_FEATURES \
        -device virtio-keyboard-pci,disable-legacy=on,disable-modern=off \
        $NETDEV_ARGS \
        $QEMU_OPT_ARG_DUMP_PACKETS \
        -chardev stdio,id=mux,mux=on,logfile=qemu.log \
        -device virtio-serial,romfile= \
        $CONSOLE_ARGS \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -monitor chardev:mux \
        -d guest_errors \
    "
    echo $QEMU_ARGS
    exit 0
fi

COMMON_QEMU_ARGS="\
    -cpu Icelake-Server,+x2apic \
    -smp ${SMP:-1} \
    -m ${MEM:-8G} \
    --no-reboot \
    -nographic \
    -display vnc=0.0.0.0:${VNC_PORT:-42} \
    -monitor chardev:mux \
    -chardev stdio,id=mux,mux=on,signal=off,logfile=qemu.log \
    $NETDEV_ARGS \
    $QEMU_OPT_ARG_DUMP_PACKETS \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -drive if=none,format=raw,id=x0,file=./test/initramfs/build/ext2.img \
    -drive if=none,format=raw,id=x1,file=./test/initramfs/build/exfat.img \
"

if [ "$1" = "iommu" ]; then
    if [ "$OVMF" = "off" ]; then
        echo "Warning: OVMF is off, enabling it for IOMMU support." 1>&2
        OVMF="on"
    fi
    IOMMU_DEV_EXTRA=",iommu_platform=on,ats=on"
    IOMMU_EXTRA_ARGS="\
        -device intel-iommu,intremap=on,device-iotlb=on \
        -device ioh3420,id=pcie.0,chassis=1 \
    "
    # TODO: Add support for enabling IOMMU on AMD platforms
fi

if [ "$MULTI_NET" = "on" ] || [ "$NETDEV" = "router-tap" ]; then
    MULTI_NET_DEVICE_ARGS="-device virtio-net-pci,netdev=net02,disable-legacy=on,disable-modern=off$VIRTIO_NET_FEATURES$IOMMU_DEV_EXTRA"
fi

if [ "$1" = "microvm" ]; then
    QEMU_ARGS="\
        $COMMON_QEMU_ARGS \
        -machine microvm,rtc=on \
        -nodefaults \
        -no-user-config \
        -device virtio-blk-device,drive=x0,serial=vext2 \
        -device virtio-blk-device,drive=x1,serial=vexfat \
        -device virtio-keyboard-device \
        -device virtio-net-device,netdev=net01 \
        -device virtio-serial-device \
        $CONSOLE_ARGS \
    "
else
    QEMU_ARGS="\
        $COMMON_QEMU_ARGS \
        -machine q35,kernel-irqchip=split \
        -device virtio-blk-pci,bus=pcie.0,addr=0x6,drive=x0,serial=vext2,disable-legacy=on,disable-modern=off,queue-size=64,num-queues=1,request-merging=off,backend_defaults=off,discard=off,write-zeroes=off,event_idx=off,indirect_desc=off,queue_reset=off$IOMMU_DEV_EXTRA \
        -device virtio-blk-pci,bus=pcie.0,addr=0x7,drive=x1,serial=vexfat,disable-legacy=on,disable-modern=off,queue-size=64,num-queues=1,request-merging=off,backend_defaults=off,discard=off,write-zeroes=off,event_idx=off,indirect_desc=off,queue_reset=off$IOMMU_DEV_EXTRA \
        -object rng-random,id=rng0,filename=/dev/urandom \
        -device virtio-rng-pci,bus=pcie.0,addr=0x8,disable-legacy=on,disable-modern=off,rng=rng0,event_idx=off,indirect_desc=off,queue_reset=off$IOMMU_DEV_EXTRA \
        -device virtio-net-pci,netdev=net01,disable-legacy=on,disable-modern=off$VIRTIO_NET_FEATURES$IOMMU_DEV_EXTRA \
        $MULTI_NET_DEVICE_ARGS \
        -device virtio-serial-pci,disable-legacy=on,disable-modern=off$IOMMU_DEV_EXTRA \
        $CONSOLE_ARGS \
        $IOMMU_EXTRA_ARGS \
    "
fi

if [ "$VSOCK" = "on" ]; then
    # RAND_CID=$(shuf -i 3-65535 -n 1)
    RAND_CID=3
    echo "[$1] Launched QEMU VM with CID $RAND_CID" 1>&2
    if [ "$1" = "microvm" ]; then
        QEMU_ARGS="$QEMU_ARGS \
            -device vhost-vsock-device,guest-cid=$RAND_CID \
        "
    else
        QEMU_ARGS="$QEMU_ARGS \
            -device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=$RAND_CID,disable-legacy=on,disable-modern=off$IOMMU_DEV_EXTRA \
        "
    fi
fi

# When using qemu-direct boot, OVMF depends on the boot protocol:
# linux-efi-* protocols require OVMF; other protocols (e.g. multiboot) do not.
if [ "$BOOT_METHOD" = "qemu-direct" ]; then
    if [ "$BOOT_PROTOCOL" = "linux-efi-pe64" ] || [ "$BOOT_PROTOCOL" = "linux-efi-handover64" ]; then
        OVMF="on"
    else
        OVMF="off"
    fi
fi

# When using `grub-rescue-iso` or `grub-qcow2` boot, OVMF must be enabled.
# Currently, the project's `grub-mkrescue` (in container image) only contained
# `x86_64-efi` platform modules — no `i386-pc`. This meant the generated ISO/qcow2
# could only be loaded by OVMF.
if [ "$BOOT_METHOD" = "grub-rescue-iso" ] || [ "$BOOT_METHOD" = "grub-qcow2" ]; then
    OVMF="on"
fi

if [ "$OVMF" = "on" ]; then
    if [ "$1" = "microvm" ]; then
        QEMU_ARGS="${QEMU_ARGS} \
            -bios /root/ovmf/release/microvm/MICROVM.fd \
        "
    else
        QEMU_ARGS="${QEMU_ARGS} \
            -bios /root/ovmf/release/OVMF.fd \
        "
    fi
fi

echo $QEMU_ARGS

# xt_udp_tls

xt_udp_tls is a netfilter/iptables match that filters QUIC traffic by the TLS server name (SNI) carried in the QUIC Initial packet. It decrypts the Initial packet, reassembles the ClientHello across packets of the same connection, and matches the SNI against a host or a host set.

## Contents
- `src/`: the kernel module `xt_udp_tls.ko`
- `ipt/`: the iptables extension `libxt_udp_tls.so`

## Build

### Prerequisites
- Kernel headers for the target kernel
- iptables development files (`xtables.h`, `pkg-config xtables`)

```bash
make            # builds src/xt_udp_tls.ko and ipt/libxt_udp_tls.so
sudo make install
```

### Cross build
```bash
# add toolchain to PATH
export PATH=/opt/toolchain/6.4-aarch64/bin:$PATH

make ARCH=arm64 KERNELRELEASE=5.10.110 CROSS_COMPILE=aarch64-linux- KERNELDIR=/path/to/kernel_src
```

## Usage

```bash
sudo insmod src/xt_udp_tls.ko          # optional: max_host_sets=100 hostset_uid=1000 hostset_gid=1000

# match one host
iptables -A FORWARD -p udp --dport 443 -m udp_tls --tls-host www.example.com -j DROP

# match a host set; it appears as /proc/net/xt_udp_tls/hostset/<name>
iptables -A FORWARD -p udp --dport 443 -m udp_tls --tls-hostset blocklist -j DROP
echo +example.com > /proc/net/xt_udp_tls/hostset/blocklist   # add
echo -example.com > /proc/net/xt_udp_tls/hostset/blocklist   # remove
echo / > /proc/net/xt_udp_tls/hostset/blocklist              # flush
```

`--log-tls` logs the matched server name.

## Third-party code
`src/aes_nohw.c` and `src/aes_nohw.h` are adapted from BoringSSL's constant-time software AES (`crypto/fipsmodule/aes/aes_nohw.c`) and keep its original copyright and ISC license notice.

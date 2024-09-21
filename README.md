- [youtubeUnblock](#youtubeunblock)
  - [Configuration](#configuration)
    - [OpenWRT pre configuration](#openwrt-pre-configuration)
    - [Entware](#entware)
    - [PC configuration](#pc-configuration)
    - [Firewall configuration](#firewall-configuration)
      - [nftables rules](#nftables-rules)
      - [Iptables rules](#iptables-rules)
    - [IPv6](#ipv6)
  - [Check it](#check-it)
  - [Flags](#flags)
  - [Troubleshooting](#troubleshooting)
    - [TV](#tv)
    - [Troubleshooting EPERMS (Operation not permitted)](#troubleshooting-eperms-operation-not-permitted)
  - [Compilation](#compilation)
  - [OpenWRT case](#openwrt-case)
    - [Building OpenWRT .ipk package](#building-openwrt-ipk-package)
    - [Building with toolchain](#building-with-toolchain)
  - [Kernel module](#kernel-module)
    - [Building kernel module](#building-kernel-module)
      - [Building on host system](#building-on-host-system)
      - [Building on any kernel](#building-on-any-kernel)
      - [Building with openwrt SDK](#building-with-openwrt-sdk)


# youtubeUnblock

Bypasses Deep Packet Inspection (DPI) systems that relies on SNI. The package is for Linux only. It is also fully compatible with routers running [OpenWRT](https://github.com/openwrt). 

The program was primarily developed to bypass YouTube Outage in Russia.

```
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

The program is distributed in two version:
- A userspace application works on top of nfnetlink queue which requires nfnetlink modules in the kernel and firewall rules. This approach is default and normally should be used but it has some limitations on embedded devices which may have no nfnetlink support. Also this solution may break down the internet speed and CPU load on your device because of jumps between userspace and kernelspace for each packet (this behavior may be fixed with connbytes but it also requires conntrack kernel module).
- A kernel module which integrates deeply within the netfilter stack and does not interact with the userspace firewall. The module requires only netfilter kernel support but it definetly present on every device connected to the Internet. The only difficulity is how to build it. I cannot provide modules within Github Actions for each single one kernel, even if we talk only about OpenWRT versions. If you want to learn more about the module, jump on [its section in the README](#kernel-module)

The program is compatible with routers based on OpenWRT, Entware(Keenetic/ASUS) and host machines. The program offers binaries via Github Actions. The binaries are also available via [github releases](https://github.com/Waujito/youtubeUnblock/releases). Use the latest pre-release for the most up to date build. Check out [Github Actions](https://github.com/Waujito/youtubeUnblock/actions/workflows/build-ci.yml) if you want to see all the binaries compiled ever. You should know the arcitecture of your hardware to use binaries. On OpenWRT you can check it with command `grep ARCH /etc/openwrt_release`.

On both OpenWRT and Entware install the program with opkg. If you got read-only filesystem error you may unpack the binary manually or specify opkg path `opkg -o <destdir>`.

For Windows use [GoodbyeDPI by ValdikSS](https://github.com/ValdikSS/GoodbyeDPI) (you can find how to use it for YouTube [here](https://github.com/ValdikSS/GoodbyeDPI/issues/378)) The same behavior is also implemented in [zapret package for linux](https://github.com/bol-van/zapret).

## Configuration

### OpenWRT pre configuration

When you got the release package, you should install it. Go to your router interface and put it in via *System-Software-install_package* menu. Go to *System-Startup* menu, restart firewall and start **youtubeUnblock**. 

To make it work you should register an iptables rule and install required kernel modules. The list of modules depends on the version of OpenWRT and which firewall do you use (iptables or nftables). 

The common dependency is
 ```text
 kmod-nfnetlink-queue
 ``` 
 but it is provided as dependency for another firewall packages. 

So, if you are on **iptables** you should install: 
```text
kmod-ipt-nfqueue
iptables-mod-nfqueue
kmod-ipt-conntrack-extra
iptables-mod-conntrack-extra
```
and of course, iptables user-space app should be available.

On **nftables** the dependencies are: 
```text
kmod-nft-queue
kmod-nf-conntrack
```

Next step is to add required firewall rules. 

For nftables on OpenWRT rules comes out-of-the-box and stored under `/usr/share/nftables.d/ruleset-post/537-youtubeUnblock.nft`. All you need is install requirements and do `/etc/init.d/firewall reload`. If no, go to [Firewall configuration](#firewall-configuration).

Now we go to the configuration. For OpenWRT here is configuration via [UCI](https://openwrt.org/docs/guide-user/base-system/uci) and [LuCI](https://openwrt.org/docs/guide-user/luci/start) available (CLI and GUI respectively).

Luci is a configuration interface for your router (which you connect when enter 192.168.1.1 in browser). LuCI configuration lives in **Services->youtubeUnblock** section. It is self descriptive, with description for each flag. Note, that after you push `Save & Apply` button, the configuration is applied automatically and the service is restarted.

UCI configuration is available in /etc/config/youtubeUnblock file, in section `youtubeUnblock.youtubeUnblock`. The configuration is done with [flags](#flags). Note, that names of flags are not the same: you should replace `-` with `_`, you shouldn't use leading `--` for flag. Also you will enable toggle flags (without parameters) with `1`. 

For example, to enable trace logs you should do
```sh
uci set youtubeUnblock.youtubeUnblock.trace=1
```

You can check the logs in CLI mode with `logread -l 200 | grep youtubeUnblock` command. 

For uci, to save the configs you should do `uci commit` and then `reload_config` to restart the youtubeUnblock

In CLI mode you will use youtubeUnblock as a normal init.d service:
for example, you can enable it with `/etc/init.d/youtubeUnblock enable`.

### Entware

For Entware on Keenetic here is an [installation guide (russian)](https://help.keenetic.com/hc/ru/articles/360021214160-%D0%A3%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0-%D1%81%D0%B8%D1%81%D1%82%D0%B5%D0%BC%D1%8B-%D0%BF%D0%B0%D0%BA%D0%B5%D1%82%D0%BE%D0%B2-%D1%80%D0%B5%D0%BF%D0%BE%D0%B7%D0%B8%D1%82%D0%BE%D1%80%D0%B8%D1%8F-Entware-%D0%BD%D0%B0-USB-%D0%BD%D0%B0%D0%BA%D0%BE%D0%BF%D0%B8%D1%82%D0%B5%D0%BB%D1%8C). Note that if your Entware router is missing netfilter queue kernel modules, here is no way to deal with it since Entware does not offer kernel modules. 

Install the binary with `opkg install youtubeUnblock-*.ipk`. After installation, the binary in /opt/bin and the init script in /opt/etc/init.d/S51youtubeUnblock will be available. To run the youtubeUnblock, simply run `/opt/etc/init.d/S51youtubeUnblock start`

### PC configuration
On local host make sure to change **FORWARD** to **OUTPUT** chain in the following Firewall rulesets.

Copy `youtubeUnblock.service` to `/usr/lib/systemd/system` (you should change the path inside the file to the program position, for example `/usr/bin/youtubeUnblock`, also you may want to delete default iptables rule addition in systemd file to controll it manually). And run `systemctl start youtubeUnblock`.

### Firewall configuration

#### nftables rules

On nftables you should put next nftables rules:
```sh
nft add chain inet fw4 youtubeUnblock '{ type filter hook postrouting priority mangle - 1; policy accept; }'
nft add rule inet fw4 youtubeUnblock 'meta l4proto { tcp, udp } th dport 443 ct original packets < 20 counter queue num 537 bypass'
nft insert rule inet fw4 output 'mark and 0x8000 == 0x8000 counter accept'
```

#### Iptables rules

On iptables you should put next iptables rules:
```sh
iptables -t mangle -N YOUTUBEUNBLOCK
iptables -t mangle -A YOUTUBEUNBLOCK -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
iptables -t mangle -A YOUTUBEUNBLOCK -p udp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
iptables -t mangle -A POSTROUTING -j YOUTUBEUNBLOCK
iptables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT
```

#### IPv6

For IPv6 on iptables you need to duplicate rules above for ip6tables:
```sh
ip6tables -t mangle -N YOUTUBEUNBLOCK
ip6tables -t mangle -A YOUTUBEUNBLOCK -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
ip6tables -t mangle -A YOUTUBEUNBLOCK -p udp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
ip6tables -t mangle -A POSTROUTING -j YOUTUBEUNBLOCK
ip6tables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT
```

Note that above rules use *conntrack* to route only first 20 packets from the connection to **youtubeUnblock**. 
If you got some troubles with it, for example **youtubeUnblock** doesn't detect YouTube, try to delete *connbytes* from the rules. But it is an unlikely behavior and you should probably check your ruleset.

You can use `--queue-balance` with multiple instances of **youtubeUnblock** for performance. This behavior is supported via multithreading. Just pass `--threads=n` where n stands for an number of threads you want to be enabled. The n defaults to **1**. The maximum threads defaults to **16** but may be altered programmatically. Note, that if you are about to increase it, here is 100% chance that you are on the wrong way.

Also [DNS over HTTPS](https://github.com/curl/curl/wiki/DNS-over-HTTPS) is preferred for additional anonymity. 

## Check it

Here is the command to test whether it working or not:
```sh
curl -o/dev/null -k --connect-to ::google.com -k -L -H Host:\ mirror.gcr.io https://test.googlevideo.com/v2/cimg/android/blobs/sha256:6fd8bdac3da660bde7bd0b6f2b6a46e1b686afb74b9a4614def32532b73f5eaa
```

It should return low speed without **youtubeUnblock** and faster with it. With **youtubeUnblock** the speed should be the same as fast with the next command:

```sh
curl -o/dev/null -k --connect-to ::google.com -k -L -H Host:\ mirror.gcr.io https://mirror.gcr.io/v2/cimg/android/blobs/sha256:6fd8bdac3da660bde7bd0b6f2b6a46e1b686afb74b9a4614def32532b73f5eaa
```

## Flags

Put flags to the **BINARY**, not an init script. If you are on OpenWRT you should put the flags inside the script: open `/etc/init.d/youtubeUnblock` with any text editor, like vi or nano and put your flags after `procd_set_param command /usr/bin/youtubeUnblock` line.

Available flags:

- `--sni-domains=<comma separated domain list>|all` List of domains you want to be handled by SNI. Use this string if you want to change default domain list. Defaults to `googlevideo.com,ggpht.com,ytimg.com,youtube.com,play.google.com,youtu.be,googleapis.com,googleusercontent.com,gstatic.com,l.google.com`. You can pass **all** if you want for every *ClientHello* to be handled. You can exclude some domains with `--exclude-domains` flag.

- `--exclude-domains=<comma separated domain list>` List of domains to be excluded from targetting.

- `--queue-num=<number of netfilter queue>` The number of netfilter queue **youtubeUnblock** will be linked to. Defaults to **537**.

- `--fake-sni={0|1}` This flag enables fake-sni which forces **youtubeUnblock** to send at least three packets instead of one with TLS *ClientHello*: Fake *ClientHello*, 1st part of original *ClientHello*, 2nd part of original *ClientHello*. This flag may be related to some Operation not permitted error messages, so before open an issue refer to [Troubleshooting for EPERMS](#troubleshooting-eperms-operation-not-permitted). Defaults to **1**.

- `--fake-sni-seq-len=<length>` This flag specifies **youtubeUnblock** to build a complicated construction of fake client hello packets. length determines how much fakes will be sent. Defaults to **1**.

- `--faking-strategy={randseq|ttl|tcp_check|pastseq|md5sum}` This flag determines the strategy of fake packets invalidation. Defaults to `randseq`
  - `randseq` specifies that random sequence/acknowledgemend random will be set. This option may be handled by provider which uses *conntrack* with drop on invalid *conntrack* state firewall rule enabled. 
  - `ttl` specifies that packet will be invalidated after `--faking-ttl=n` hops. `ttl` is better but may cause issues if unconfigured. 
  - `pastseq` is like `randseq` but sequence number is not random but references the packet sent in the past (before current).
  - `tcp_check` will invalidate faking packet with invalid checksum. May be handled and dropped by some providers/TSPUs.
  - `md5sum` will invalidate faking packet with invalid TCP md5sum. md5sum is a TCP option which is handled by the destination server but may be skipped by TSPU.

- `--faking-ttl=<ttl>` Tunes the time to live (TTL) of fake SNI messages. TTL is specified like that the packet will go through the DPI system and captured by it, but will not reach the destination server. Defaults to **8**.

- `--fake-seq-offset` Tunes the offset from original sequence number for fake packets. Used by randseq faking strategy. Defaults to 10000. If 0, random sequence number will be set.

- `--frag={tcp,ip,none}` Specifies the fragmentation strategy for the packet. tcp is used by default. Ip fragmentation may be blocked by DPI system. None specifies no fragmentation. Probably this won't work, but may be will work for some fake sni strategies.

- `--frag-sni-reverse={0|1}` Specifies **youtubeUnblock** to send *ClientHello* fragments in the reverse order. Defaults to **1**.

- `--frag-sni-faked={0|1}` Specifies **youtubeUnblock** to send fake packets near *ClientHello* (fills payload with zeroes). Defaults to **0**.

- `--frag-middle-sni={0|1}` With this options **youtubeUnblock** will split the packet in the middle of SNI data. Defaults to 1.

- `--frag-sni-pos=<pos>` With this option **youtubeUnblock** will split the packet at the position pos. Defaults to 1.

- `--quic-drop` Drop all QUIC packets which goes to youtubeUnblock. Won't affect any other UDP packets. Suitable for some TVs. Note, that for this option to work you should also add proxy udp to youtubeUnblock in firewall. `connbytes` may also be used with udp.

- `--fk-winsize=<winsize>` Specifies window size for the fragmented TCP packet. Applicable if you want for response to be fragmented. May slowdown connection initialization.

- `--synfake={1|0}` If 1, syn payload will be sent before each request. The idea is taken from syndata from zapret project. Syn payload will normally be discarded by endpoint but may be handled by TSPU. This option sends normal fake in that payload. Please note, that the option works for all the sites, so --sni-domains won't change anything.

- `--synfake-len=<len>` The fake packet sent in synfake may be too large. If you experience issues, lower up synfake-len. where len stands for how much bytes should be sent as syndata. Pass 0 if you want to send an entire fake packet. Defaults to 0

- `--sni-detection={parse|brute}` Specifies how to detect SNI. Parse will normally detect it by parsing the Client Hello message. Brute will go through the entire message and check possibility of SNI occurrence. Please note, that when `--sni-domains` option is not all brute will be O(nm) time complexity where n stands for length of the message and m is number of domains. Defaults to parse.

- `--seg2delay=<delay>` This flag forces **youtubeUnblock** to wait a little bit before send the 2nd part of the split packet.

- `--silent` Disables verbose mode.

- `--trace` Maximum verbosity for debugging purposes.

- `--no-gso` Disables support for Google Chrome fat packets which uses GSO. This feature is well tested now, so this flag probably won't fix anything.

- `--no-ipv6` Disables support for ipv6. May be useful if you don't want for ipv6 socket to be opened.

- `--threads=<threads number>` Specifies the amount of threads you want to be running for your program. This defaults to **1** and shouldn't be edited for normal use. If you have performance issues, consult [performance chaptr](https://github.com/Waujito/youtubeUnblock?tab=readme-ov-file#performance)

- `--packet-mark=<mark>` Use this option if youtubeUnblock conflicts with other systems rely on packet mark. Note that you may want to change accept rule for iptables to follow the mark.

## Troubleshooting

If you got troubles with some sites and you sure that they are blocked by SNI (youtube for example), use may play around with [flags](#flags) and their combinations. At first it is recommended to try `--faking-strategy` flag and `--frag-sni-faked=1`.
If you have troubles with some sites being proxied, you can play with flags values. For example, for someone `--faking-strategy=ttl` works. You should specify proper `--fake-sni-ttl=<ttl value>` where ttl is the amount of hops between you and DPI.

If you are on Chromium you may have to disable *kyber* (the feature that makes the TLS *ClientHello* very big). I've got the problem with it on router, so to escape possible errors, so it is better to disable it: in `chrome://flags` search for kyber and switch it to disabled state. Alternatively you may set `--sni-detection=brute` and probably adjust `--sni-domains` flag.

If your browser is using QUIC it may not work properly. Disable it in Chrome in `chrome://flags` and in Firefox `network.http.http{2,3}.enable(d)` in `about:config` option.

It seems like some TSPUs started to block wrongseq packets, so you should play around with faking strategies. I personally recommend to start with `md5sum` faking strategy.

### TV

Televisions are the biggest headache. 

In [this issue](https://github.com/Waujito/youtubeUnblock/issues/59) the problem has been resolved. And now youtubeUnblock should work with default flags. If not, play around with faking strategies and other flags. Also you might be have to disable QUIC. To do it you may use `--quic-drop` [flag](#flags) with proper firewall configuration (check description of the flag). Note, that this flag won't disable gQUIC and some TVs may relay on it. To disable gQUIC you will need to block the entire 443 port for udp in firewall configuration:

For **nftables** do
```
nft insert rule inet fw4 forward ip saddr 192.168.. udp dport 443 counter drop
```

For **iptables**
```
iptables -I OUTPUT --src 192.168.. -p udp --dport 443 -j DROP
```

Where you have to replace 192.168.. with ip of your television.

### Troubleshooting EPERMS (Operation not permitted)

*EPERM* may occur in a lot of places but generally here are two: *mnl_cb_run* and when sending the packet via *rawsocket* (raw_frags_send and send fake sni).

- **mnl_cb_run** *Operation not permitted* indicates that another instance of youtubeUnblock is running on the specified queue-num.

- **rawsocket** *Operation not permitted* indicates that the packet is being dropped by nefilter rules. In fact this is a hint from the kernel that something wrong is going on and we should check the firewall rules. Before dive into the problem let's make it clean how the mangled packets are being sent. Nefilter queue provides us with the ability to mangle the packet on fly but that is not suitable for this program because we need to split the packet to at least two independent packets. So we are using [linux raw sockets](https://man7.org/linux/man-pages/man7/raw.7.html) which allows us to send any ipv4 packet. **The packet goes from the OUTPUT chain even when NFQUEUE is set up on FORWARD (suitable for OpenWRT).** So we need to escape packet rejects here.
    * raw_frags_send EPERM: just make sure outgoing traffic is allowed (RELATED,ESTABLISHED should work, if not, go to step 3)
    * send fake sni EPERM: Fake SNI is out-of-state thing and will likely corrupt the connection (the behavior is expected). conntrack considers it as an invalid packet. By default OpenWRT set up to drop outgoing packets like this one. You may delete nftables/iptables rule that drops packets with invalid conntrack state, but I don't recommend to do this. The step 3 is better solution.
    * Step 3, ultimate solution. Use mark (don't confuse with connmark). The youtubeUnblock uses mark internally to avoid infinity packet loops (when the packet is sent by youtubeUnblock but on next step handled by itself). Currently it uses mark (1 << 15) = 32768. You should put iptables/nftables that ultimately accepts such marks at the very start of the filter OUTPUT chain: `iptables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT` or `nft insert rule inet fw4 output mark and 0x8000 == 0x8000 counter accept`.

## Compilation

Before compilation make sure `gcc`, `make`, `autoconf`, `automake`, `pkg-config` and `libtool` is installed. For Fedora `glibc-static` should be installed as well.

Compile with `make`. Install with `make install`. The package include `libnetfilter_queue`, `libnfnetlink` and `libmnl` as static dependencies. The package requires `linux-headers` and kernel built with netfilter nfqueue support.

## OpenWRT case

The package is also compatible with routers. The router should be running by linux-based system such as [OpenWRT](https://openwrt.org/).

You can build under OpenWRT with two options: first - through the SDK, which is preferred way and second is cross-compile manually with OpenWRT toolchain.

### Building OpenWRT .ipk package

OpenWRT provides a high-level SDK for the package builds. 

First step is to download or compile OpenWRT SDK for your specific platform. The SDK can be compiled according to [this tutorial](https://openwrt.org/docs/guide-developer/toolchain/using_the_sdk). 

Beside of raw source code of SDK, OpenWRT also offers precompiled SDKs for your router. You can find it on the router page. For example, I have ramips/mt76x8 based router so for me the sdk is on https://downloads.openwrt.org/releases/23.05.3/targets/ramips/mt76x8/ and called `openwrt-sdk-23.05.3-ramips-mt76x8_gcc-12.3.0_musl.Linux-x86_64`. 

You will need to [install sdk requirements on your system](https://openwrt.org/docs/guide-developer/toolchain/install-buildsystem) If you have any problems, use docker ubuntu:24.04 image. Make sure to be a non-root user since some makesystem fails with it. Next, untar the SDK and cd into it. 

Do 
```sh
echo "src-git youtubeUnblock https://github.com/Waujito/youtubeUnblock.git;openwrt" >> feeds.conf
./scripts/feeds update youtubeUnblock
./scripts/feeds install -a -p youtubeUnblock
make package/youtubeUnblock/compile 
```

Now the packet is built and you can import it to the router. Find it in `bin/packages/<target>/youtubeUnblock/youtubeUnblock-<version>.ipk`. 

### Building with toolchain

The precompiled toolchain located near the SDK. For example it is called `openwrt-toolchain-23.05.3-ramips-mt76x8_gcc-12.3.0_musl.Linux-x86_64.tar.xz`. When you download the toolchain, untar it somewhere. Now we are ready for compilation. My cross gcc asked me to create a staging dir for it and pass it as an environment variable. Also you should notice toolsuite packages and replace my make command with yours. 

```
STAGING_DIR=temp make CC=/usr/bin/mipsel-openwrt-linux-gcc LD=/usr/bin/mipsel-openwrt-linux-ld AR=/usr/bin/mipsel-openwrt-linux-ar OBJDUMP=/usr/bin/mipsel-openwrt-linux-objdump NM=/usr/bin/mipsel-openwrt-linux-nm STRIP=/usr/bin/mipsel-openwrt-linux-strip CROSS_COMPILE_PLATFORM=mipsel-buildroot-linux-gnu
```

Take a look at `CROSS_COMPILE_PLATFORM` It is required by autotools but I think it is not necessary. Anyways I put `mipsel-buildroot-linux-gnu` in here. For your router model name maybe an [automake cross-compile manual](https://www.gnu.org/software/automake/manual/html_node/Cross_002dCompilation.html) will be helpful. 

When compilation is done, the binary file will be in build directory. Copy it to your router. Note that a ssh access is likely to be required to proceed. *sshfs* don't work on my model so I injected the application to the router via *Software Upload Package* page. It has given me an error, but also a `/tmp/upload.ipk` file which I copied in root directory, `chmod +x` it and run.

## Kernel module

This section describes the kernel module version of youtubeUnblock. The kernel module operates as a normal module inside the kernel and integrates within the netfilter stack to statelessly mangle the packets sent over the Internet.

You can configure the module with its flags in insmod:
```
insmod kyoutubeUnblock.ko fake_sni=1 exclude_domains=.ru quic_drop=1
```

Note that the flags names are different from ones used for the regular youtubeUnblock(right like in UCI configuration for OpenWRT): replace `-` with `_` and no leading `--`. Also to configure togglers you should set them to `1` (`silent=1 quic_drop=1`)

Also a drop in replacement is supported for all the parameters excluding packet mark. A drop in replacement does not require module restart if you want to change the parameters. You can specify and check the parameters within module's directory inside the sysfs: `/sys/module/kyoutubeUnblock/parameters/`. For example, to set quic_drop to true you may use next command:
```sh
echo 1 | sudo tee /sys/module/kyoutubeUnblock/parameters/quic_drop
```
and 
```sh
cat /sys/module/kyoutubeUnblock/parameters/quic_drop
```
to check the parameter.

### Building kernel module

#### Building on host system

To build the kernel module on your host system you should install `linux-headers` which will provide build essential tools and `gcc` compiler suite. On host system you may build the module with 
```sh
make kmake
```

#### Building on any kernel

To build the module for external kernel you should build that kernel locally and point make to it. Use `KERNEL_BUILDER_MAKEDIR=~/linux` flag for make, for example:
```
make kmake KERNEL_BUILDER_MAKEDIR=~/linux
```
Note, that the kernel should be already configured and built. See linux kernel building manuals for more information about your specific case.

#### Building with openwrt SDK

Building with openwrt SDK is not such a hard thing. The only thing you should do is to obtain the sdk. You can find it by looking to your architecture and version of the openwrt currently used. You should use the exactly your version of openwrt since kernels there change often. You can find the sdk in two ways: by downloading it from their site or by using the openwrt sdk docker container (recommended).

If you decide to download the tar archive, follow next steps:
For me the archive lives in https://downloads.openwrt.org/releases/23.05.3/targets/ramips/mt76x8/ and called `openwrt-sdk-23.05.3-ramips-mt76x8_gcc-12.3.0_musl.Linux-x86_64`. You will need to [install sdk requirements on your system](https://openwrt.org/docs/guide-developer/toolchain/install-buildsystem) If you have any problems, use docker ubuntu:24.04 image. Make sure to be a non-root user since some makesystem fails with it. Next, untar the SDK and cd into it. 

Or you can obtain the docker image with sdk built-in: [https://hub.docker.com/u/openwrt/sdk](https://hub.docker.com/u/openwrt/sdk). In my case the image has tag `ramips-mt76x8-23.05.3`. A good thing here is that you don't need to install any dependencies inside the docker container. Also docker hub has a perfect search around tags if you don't sure which one corresponds to your device.

When you unpacked/installed the sdk, you is ready to start with building the kernel module.

Do
```sh
echo "src-git youtubeUnblock https://github.com/Waujito/youtubeUnblock.git;openwrt" >> feeds.conf
./scripts/feeds update youtubeUnblock
./scripts/feeds install -a -p youtubeUnblock
make defconfig
make package/kyoutubeUnblock/compile V=s
```

When the commands finish, the module is ready. Find it with `find bin -name "kmod-youtubeUnblock*.ipk"`, copy to your host and install to the router via gui software interface. The module should start immediately. If not, do `modprobe kyoutubeUnblock`.

 >If you have any questions/suggestions/problems feel free to open an [issue](https://github.com/Waujito/youtubeUnblock/issues).

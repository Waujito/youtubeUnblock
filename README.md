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
  - [UDP/QUIC](#udpquic)
  - [Troubleshooting](#troubleshooting)
    - [TV](#tv)
    - [Troubleshooting EPERMS (Operation not permitted)](#troubleshooting-eperms-operation-not-permitted)
    - [Conntrack](#conntrack-troubleshooting)
    - [NAT Hardware/Software offloading](#nat-hardwaresoftware-offloading)
  - [Compilation](#compilation)
  - [OpenWRT case](#openwrt-case)
    - [Building OpenWRT .ipk package](#building-openwrt-ipk-package)
    - [Building with toolchain](#building-with-toolchain)
  - [Kernel module](#kernel-module)
    - [Building kernel module](#building-kernel-module)
      - [Building on host system](#building-on-host-system)
      - [Building on any kernel](#building-on-any-kernel)
      - [Building with openwrt SDK](#building-with-openwrt-sdk)
  - [Padavan](#padavan)


# youtubeUnblock

Bypasses YouTube detection systems that rely on SNI. 

The program was primarily developed to bypass YouTube Outage in Russia.

The program should be used **only for the YouTube platform**. It is legal since access to YouTube **is not officially restricted in Russia**. You **MUST NOT** use the program for any other purpose. I respect all Russian laws and do not wish to break any.

Starting with a YouTube speedup for my laptop, this project grew into a standalone tool that unblocks YouTube on a wide variety of devices. This project has fulfilled my dream of creating a massive, highly reliable, open-source GitHub project that helps people. I value all your feedback, and that is the reason I continue to maintain it. I learned many things while developing it, such as aspects of the Linux kernel networking stack. It is truly rewarding to explore new technologies while developing a project for people. This experience is incomparable to that of working on a mere pet project.

**So, please use it only for YouTube and only in accordance with the laws of your country.**

If you have any questions, suggestions, or problems, feel free to open an [issue](https://github.com/Waujito/youtubeUnblock/issues).

You are also welcome to contact me directly using the links provided in my GitHub profile description; however, please contact me only if you have a special offer. For help with the program, it is preferable to make our conversation public by posting on [GitHub Discussions](https://github.com/Waujito/youtubeUnblock/discussions).

The program is distributed under the GNU GPL v3 open-source license.

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

The program is for Linux only. It is also fully compatible with routers running [OpenWRT](https://github.com/openwrt). 

The program is distributed in two version:
- A userspace application works on top of nfnetlink queue which requires nfnetlink modules in the kernel and firewall rules. This approach is default and normally should be used but it has some limitations on embedded devices which may have no nfnetlink support. Also this solution may break down the internet speed and CPU load on your device because of jumps between userspace and kernelspace for each packet (this behavior may be fixed with connbytes but it also requires conntrack kernel module).
- A kernel module which integrates deeply within the netfilter stack and does not interact with the userspace firewall. The module requires only netfilter kernel support but it definetly present on every device connected to the Internet. The only difficulity is how to build it. I cannot provide modules within Github Actions for each single one kernel, even if we talk only about OpenWRT versions. If you want to learn more about the module, jump on [its section in the README](#kernel-module). Whats the benefits of the kernel module? The benefits come for some specific cases: the kernel module is the fastest thing that allows us to process every single packet sent to the linux network stack, while the normal youtubeUnblock requires connbytes to keep the internet speed. Speaking about connbytes, it also requires conntrack to operate, which may be a limitation on some transit-traffic machines. Also userspace youtubeUnblock requires modules for netlink queue, userspace firewall application and modules for it. The kernel module is much simpler and requires only the linux kernel with netfilter built in.

The program is compatible with routers based on OpenWRT, Entware(Keenetic/ASUS) and host machines. The program offers binaries via Github Actions. The binaries are also available via [github releases](https://github.com/Waujito/youtubeUnblock/releases). Use the latest pre-release for the most up to date build. Check out [Github Actions](https://github.com/Waujito/youtubeUnblock/actions/workflows/build-ci.yml) if you want to see all the binaries compiled ever. You should know the arcitecture of your hardware to use binaries. On OpenWRT you can check it with command `grep ARCH /etc/openwrt_release`.

On both OpenWRT and Entware install the program with opkg. If you got read-only filesystem error you may unpack the binary manually or specify opkg path `opkg -o <destdir>`.

## Configuration

### OpenWRT pre configuration

When you got the release package, you should install it. Go to your router interface, to *System->Software*, do *Update lists* and install youtubeUnblock via *install_package* button. Then, you should go to *System-Startup* menu and reload the firewall (You may also do it within *Services->youtubeUnblock* menu). 

Since OpenWRT **main** branch switched to apk instead of opkg, but this is not released yet, here is not deploys for apk in **Releases**. But **apk is supported** in PR #196.

To make it work you should register an iptables rule and install required kernel modules. The list of modules depends on the version of OpenWRT and which firewall do you use (iptables or nftables). For most modern versions of OpenWRT (v23.x, v22.x) you should use nftables rules, for older ones it depends, but typically iptables.

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

For **LuCI** aka **GUI** aka **web-interface of router** you should install **luci-app-youtubeUnblock** package like you did it with the normal youtubeUnblock package. Note, that lists of official opkg feeds should be loaded (**Do it with Update lists option**).

If you got ` * pkg_hash_check_unresolved: cannot find dependency luci-lua-runtime for luci-app-youtubeUnblock` error, you are using old openwrt. Install [this dummy package](https://github.com/xiaorouji/openwrt-passwall/files/12605732/luci-lua-runtime_all_fake.zip). [Check this comment](https://github.com/Waujito/youtubeUnblock/issues/168#issuecomment-2449227547) for more details.

LuCI configuration lives in **Services->youtubeUnblock** section. It is self descriptive, with description for each flag. Note, that after you push `Save & Apply` button, the configuration is applied automatically and the service is restarted.

UCI configuration is available in /etc/config/youtubeUnblock file, in section `youtubeUnblock.youtubeUnblock`. You may pass any args as a string to parameter `args`, but before it disable interactive flags (You can configurate with it but it is a way harder and I recommend to use it only with `luci-app-youtubeUnblock`):

```sh
uci set youtubeUnblock.youtubeUnblock.conf_strat="args"
uci set youtubeUnblock.youtubeUnblock.args="--queue-num=537 --threads=1"
```

To save the configs you should do `uci commit` and then `reload_config` to restart youtubeUnblock


You can check the logs in CLI mode with `logread -l 200 | grep youtubeUnblock` command. 

In CLI mode you will use youtubeUnblock as a normal init.d service:
for example, you can enable it with `/etc/init.d/youtubeUnblock enable`.

### Entware

For Entware on Keenetic here is an [installation guide (russian)](https://help.keenetic.com/hc/ru/articles/360021214160-%D0%A3%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0-%D1%81%D0%B8%D1%81%D1%82%D0%B5%D0%BC%D1%8B-%D0%BF%D0%B0%D0%BA%D0%B5%D1%82%D0%BE%D0%B2-%D1%80%D0%B5%D0%BF%D0%BE%D0%B7%D0%B8%D1%82%D0%BE%D1%80%D0%B8%D1%8F-Entware-%D0%BD%D0%B0-USB-%D0%BD%D0%B0%D0%BA%D0%BE%D0%BF%D0%B8%D1%82%D0%B5%D0%BB%D1%8C).

Install the binary with `opkg install youtubeUnblock-*.ipk`. After installation, the binary in /opt/bin and the init script in /opt/etc/init.d/S51youtubeUnblock will be available. To run the youtubeUnblock, simply run `/opt/etc/init.d/S51youtubeUnblock start`

### NFNETLINK_QUEUE kernel modules

Note, that you should feed the target kernel with nfnetlink_queue kernel module. The module may be disabled or even not present. Entware S51youtubeUnblock will try to insert kmods any way but if they are not provided by software, you should install them manually. AFAIK on keenetics here is a repository with modules compiled by customer. You can find them somewhere in the web interface of your device. On other routers you may want to do deeper research in that case and find your kmods. If you can't find anything, you may ask the customer for GPL codes of linux kernel (and may be even OpenWRT) and compile kmods manually.

You should insert the module with (this step may be omitted on Entware and OpenWRT):
```sh
modprobe nfnetlink_queue
```

### PC configuration
On local host make sure to change **FORWARD** to **OUTPUT** chain in the following Firewall rulesets.

Copy `youtubeUnblock.service` to `/usr/lib/systemd/system` (you should change the path inside the file to the program position, for example `/usr/bin/youtubeUnblock`, also you may want to delete default iptables rule addition in systemd file to controll it manually). And run `systemctl start youtubeUnblock`.

### Firewall configuration

#### nftables rules

On nftables you should put next nftables rules:
```sh
nft add chain inet fw4 youtubeUnblock '{ type filter hook postrouting priority mangle - 1; policy accept; }'
nft add rule inet fw4 youtubeUnblock 'tcp dport 443 ct original packets < 20 counter queue num 537 bypass'
nft add rule inet fw4 youtubeUnblock 'meta l4proto udp ct original packets < 9 counter queue num 537 bypass'
nft insert rule inet fw4 output 'mark and 0x8000 == 0x8000 counter accept'
```

#### Iptables rules

On iptables you should put next iptables rules:
```sh
iptables -t mangle -N YOUTUBEUNBLOCK
iptables -t mangle -A YOUTUBEUNBLOCK -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
iptables -t mangle -A YOUTUBEUNBLOCK -p udp -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:8 -j NFQUEUE --queue-num 537 --queue-bypass
iptables -t mangle -A POSTROUTING -j YOUTUBEUNBLOCK
iptables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT
```

#### IPv6

For IPv6 on iptables you need to duplicate rules above for ip6tables:
```sh
ip6tables -t mangle -N YOUTUBEUNBLOCK
ip6tables -t mangle -A YOUTUBEUNBLOCK -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
ip6tables -t mangle -A YOUTUBEUNBLOCK -p udp -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:8 -j NFQUEUE --queue-num 537 --queue-bypass
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
#### General flags
Flags that do not scoped to a specific section, used over all the youtubeUnblock

- `--queue-num=<number of netfilter queue>` The number of netfilter queue **youtubeUnblock** will be linked to. Defaults to **537**.

- `--silent` Disables verbose mode.

- `--trace` Maximum verbosity for debugging purposes.

- `--instaflush` Used with tracing. Flushes the buffer instantly, without waiting for explicit new line. Highly useful for debugging crushes.

- `--no-gso` Disables support for TCP fat packets which uses GSO. This feature is well tested now, so this flag probably won't fix anything.

- `--use-conntrack` Enables support for conntrack in youtubeUnblock. Disabled by default. Enabled in kernel module.

- `--no-ipv6` Disables support for ipv6. May be useful if you don't want for ipv6 socket to be opened.

- `--threads=<threads number>` Specifies the amount of threads you want to be running for your program. This defaults to **1** and shouldn't be edited for normal use. But if you really want multiple queue instances of youtubeUnblock, note that you should change --queue-num to --queue balance. For example, with 4 threads, use `--queue-balance 537:540` on iptables and `queue num 537-540` on nftables.

- `--connbytes-limit=<pkts>` **Kernel module only!** Specify how much packets of connection should be processed by kyoutubeUnblock. Pass 0 if you want for each packet to be processed. This flag may be useful for UDP traffic since unlimited youtubeUnblock may lead to traffic flood and unexpected bans. Defaults to 19. In most cases you don't want to change it.

- `--daemonize` Daemonizes the youtubeUnblock (forks and detaches it from the shell). Terminate the program with `killall youtubeUnblock`. If you want to track the logs of youtubeUnblock in logread or journalctl, use **--syslog** flag.

- `--syslog` Redirects logs to the system log. You can read it with `journalctl` or `logread`.

- `--noclose` Usable only with `--daemonize`. Will not redirect io streams to /dev/null.

- `--packet-mark=<mark>` Use this option if youtubeUnblock conflicts with other systems rely on packet mark. Note that you may want to change accept rule for iptables to follow the mark.

#### Section scoped flags

- `--fbegin` and `--fend` flags: youtubeUnblock supports multiple sets of strategies for specific filters. You may want to initiate a new set after the default one, like: `--sni-domains=googlevideo.com --faking-strategy=md5sum --fbegin --sni-domains=youtube.com --faking-strategy=tcp_check --fbegin --sni-domains=l.google.com --faking-strategy=pastseq`. Note, that the priority of these sets goes backwards: last is first, default (one that does not start with --fbegin) is last. If you start the new section, the default settings are implemented just like youtubeUnblock without any parameters. Note that the config above is just an example and won't work for you.

- `--tls={enabled|disabled}` Set it if you want not to process TLS traffic in current section. May be used if you want to set only UDP-based section. (Here section is a unit between `--fbegin` and `--fend` flags).

- `--fake-sni={0|1}` This flag enables fake-sni which forces **youtubeUnblock** to send at least three packets instead of one with TLS *ClientHello*: Fake *ClientHello*, 1st part of original *ClientHello*, 2nd part of original *ClientHello*. This flag may be related to some Operation not permitted error messages, so before open an issue refer to [Troubleshooting for EPERMS](#troubleshooting-eperms-operation-not-permitted). Defaults to **1**.

- `--fake-sni-seq-len=<length>` This flag specifies **youtubeUnblock** to build a complicated construction of fake client hello packets. length determines how much fakes will be sent. Defaults to **1**.

- `--fake-sni-type={default|custom|random}` This flag specifies which faking message type should be used for fake packets. For `random`, the message of random length and with random payload will be sent. For `default` the default payload (sni=www.google.com) is used. And for the `custom` option, the payload from `--fake-custom-payload` section utilized. Defaults to `default`.

- `--fake-custom-payload=<payload>` Useful with `--fake-sni-type=custom`. You should specify the payload for fake message manually. Use hex format: `--fake-custom-payload=0001020304` mean that 5 bytes sequence: `0x00`, `0x01`, `0x02`, `0x03`, `0x04` used as fake.

- `--fake-custom-payload-file=<binary file containing TLS message>` Same as `--fake-custom-payload` but binary file instead of hex. The file should contain raw binary TLS message (TCP payload).

- `--faking-strategy={randseq|ttl|tcp_check|pastseq|md5sum}` This flag determines the strategy of fake packets invalidation. Defaults to `randseq`
  - `randseq` specifies that random sequence/acknowledgment random will be set. This option may be handled by provider which uses *conntrack* with drop on invalid *conntrack* state firewall rule enabled. 
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

- `--fk-winsize=<winsize>` Specifies window size for the fragmented TCP packet. Applicable if you want for response to be fragmented. May slowdown connection initialization.

- `--synfake={1|0}` If 1, syn payload will be sent before each request. The idea is taken from syndata from zapret project. Syn payload will normally be discarded by endpoint but may be handled by TSPU. This option sends normal fake in that payload. Please note, that the option works for all the sites, so --sni-domains won't change anything.

- `--synfake-len=<len>` The fake packet sent in synfake may be too large. If you experience issues, lower up synfake-len. where len stands for how much bytes should be sent as syndata. Pass 0 if you want to send an entire fake packet. Defaults to 0

- `--sni-detection={parse|brute}` Specifies how to detect SNI. Parse will normally detect it by parsing the Client Hello message. Brute will go through the entire message and check possibility of SNI occurrence. Please note, that when `--sni-domains` option is not all brute will be O(nm) time complexity where n stands for length of the message and m is number of domains. Defaults to parse.

- `--seg2delay=<delay>` This flag forces **youtubeUnblock** to wait a little bit before send the 2nd part of the split packet.

- `--sni-domains=<comma separated domain list>|all` List of domains you want to be handled by SNI. Use this string if you want to change default domain list. Defaults to `googlevideo.com,ggpht.com,ytimg.com,youtube.com,play.google.com,youtu.be,googleapis.com,googleusercontent.com,gstatic.com,l.google.com`. You can pass **all** if you want for every *ClientHello* to be handled. You can exclude some domains with `--exclude-domains` flag.

- `--exclude-domains=<comma separated domain list>` List of domains to be excluded from targeting.

- `--sni-domains-file=<file contains comma or new-line separated list>` Same as `--sni-domains` but accepts path to container file instead of inline domains list. The format is file may consist of both comma-separated domains list as well as new-line separated list.

- `--exclude-domains-file=<file contains comma or new-line separated list>` Same as `--exclude-domains` but accepts path to container file instead of inline domains list. The format is file may consist of both comma-separated domains list as well as new-line separated list.

- `--udp-mode={drop|fake}` This flag specifies udp handling strategy. If drop udp packets will be dropped (useful for quic when browser can fallback to tcp), if fake udp will be faked. Defaults to fake.

- `--udp-fake-seq-len=<amount of faking packets sent>` Specifies how much faking packets will be sent over the network. Defaults to 6.

- `--udp-fake-len=<size of udp fake>` Size of udp fake payload (typically payload is zeroes). Defaults to 64.

- `--udp-dport-filter=<5,6,200-500>` Filter the UDP destination ports. Defaults to no ports. Specifie the ports you want to be handled by youtubeUnblock.

- `--udp-faking-strategy={checksum|ttl|none}` Faking strategy for udp. `checksum` will fake UDP checksum, `ttl` won't fake but will make UDP content relatively small, `none` is no faking. Defaults to none.

- `--udp-filter-quic={disabled|all|parse}` Enables QUIC filtering for UDP handler. If disabled, quic won't be processed, if all, all quic initial packets will be handled. `parse` will decrypt and parse QUIC initial message and match it with `--sni-domains`. Defaults to disabled.

- `--quic-drop` Drop all QUIC packets which goes to youtubeUnblock. Won't affect any other UDP packets. Just an alias for `--udp-filter-quic=all --udp-mode=drop`.

- `--no-dport-filter` By default, youtubeUnblock will filter for TLS and QUIC 443. If you want to disable it, pass this flag. (this does not affect `--udp-dport-filter`)

## UDP/QUIC

UDP is another communication protocol. Well-known technologies that use it are DNS, QUIC. UDP does not provide reliable connection and its header is much simpler than TCP thus fragmentation is limited. The support provided primarily by faking. 

**For UDP faking in kernel module** Make sure to decrease `--connbytes-limit` up to 5. This will allow not to process additional packets and prevent network flood.

Right now, QUIC faking may not work well, so use `--udp-mode=drop` option.

QUIC is enabled with `--udp-filter-quic` flag. The flag supports two modes: `all` will handle all the QUIC initial messages and `parse` will decrypt and parse the QUIC initial message, and then compare it with `--sni-domains` flag.

**I recommend to use** `--udp-mode=drop --udp-filter-quic=parse`.

For **other UDP protocols** I recommend to configure UDP support in the separate section from TCP, like `--fbegin --udp-dport-filter=50000-50099 --tls=disabled`.

## Troubleshooting

Check up [this issue](https://github.com/Waujito/youtubeUnblock/issues/148) for useful configs.

If you got troubles with some sites and you sure that they are blocked by SNI (youtube for example), use may play around with [flags](#flags) and their combinations. At first it is recommended to try `--faking-strategy` flag and `--frag-sni-faked=1`.
If you have troubles with some sites being proxied, you can play with flags values. For example, for someone `--faking-strategy=ttl` works. You should specify proper `--fake-sni-ttl=<ttl value>` where ttl is the amount of hops between you and DPI.

If you are on Chromium you may have to disable *kyber* (the feature that makes the TLS *ClientHello* very big). I've got the problem with it on router, so to escape possible errors, so it is better to disable it: in `chrome://flags` search for kyber and switch it to disabled state. Alternatively you may set `--sni-detection=brute` and probably adjust `--sni-domains` flag.

*Kyber* on firefox disables with `security.tls.enable_kyber` in `about:config`.

If your browser is using QUIC it may not work properly. Disable it in Chrome in `chrome://flags` and in Firefox `network.http.http{2,3}.enable(d)` in `about:config` option.

It seems like some TSPUs started to block wrongseq packets, so you should play around with faking strategies. I personally recommend to start with `md5sum` faking strategy.

#### youtube with `--sni-domains=all`

I know about this issue but it is **basically not an youtubeUnblock problem**. The problem is behind the large `*.googlevideo.com` domain name. All you want is to create a new configuration section for only youtube. It should go after section for all domains. For plain string arguments just `--fbegin` at the end of args list will work. In luci you can create section interactively.

### TV

Televisions are the biggest headache. 

In [this issue](https://github.com/Waujito/youtubeUnblock/issues/59) the problem has been resolved. And now youtubeUnblock should work with default flags. If not, play around with faking strategies and other flags. Also you might be have to disable QUIC. To do it you may use `--quic-drop` [flag](#flags) with proper firewall configuration (check description of the flag). Note, that this flag won't disable gQUIC and some TVs may relay on it. To disable gQUIC you will need to block the entire 443 port for udp in firewall configuration:

For **nftables** do
```
nft insert rule inet fw4 forward ip saddr 192.168.. udp dport 443 counter drop
```

For **iptables**
```
iptables -I FORWARD --src 192.168.. -p udp --dport 443 -j DROP
```

Where you have to replace 192.168.. with ip of your television.

### Troubleshooting EPERMS (Operation not permitted)

*EPERM* may occur in a lot of places but generally here are two: *mnl_cb_run* and when sending the packet via *rawsocket* (raw_frags_send and send fake sni).

- **mnl_cb_run** *Operation not permitted* indicates that another instance of youtubeUnblock is running on the specified queue-num.

- **rawsocket** *Operation not permitted* indicates that the packet is being dropped by nefilter rules. In fact this is a hint from the kernel that something wrong is going on and we should check the firewall rules. Before dive into the problem let's make it clean how the mangled packets are being sent. Nefilter queue provides us with the ability to mangle the packet on fly but that is not suitable for this program because we need to split the packet to at least two independent packets. So we are using [linux raw sockets](https://man7.org/linux/man-pages/man7/raw.7.html) which allows us to send any ipv4 packet. **The packet goes from the OUTPUT chain even when NFQUEUE is set up on FORWARD (suitable for OpenWRT).** So we need to escape packet rejects here.
    * raw_frags_send EPERM: just make sure outgoing traffic is allowed (RELATED,ESTABLISHED should work, if not, go to step 3)
    * send fake sni EPERM: Fake SNI is out-of-state thing and will likely corrupt the connection (the behavior is expected). conntrack considers it as an invalid packet. By default OpenWRT set up to drop outgoing packets like this one. You may delete nftables/iptables rule that drops packets with invalid conntrack state, but I don't recommend to do this. The step 3 is better solution.
    * Step 3, ultimate solution. Use mark (don't confuse with connmark). The youtubeUnblock uses mark internally to avoid infinity packet loops (when the packet is sent by youtubeUnblock but on next step handled by itself). Currently it uses mark (1 << 15) = 32768. You should put iptables/nftables that ultimately accepts such marks at the very start of the filter OUTPUT chain: `iptables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT` or `nft insert rule inet fw4 output mark and 0x8000 == 0x8000 counter accept`.

### Conntrack troubleshooting

youtubeUnblock *optionally* depends on conntrack. 
For kernel module, if conntrack breaks dependencies, compile it with `make kmake EXTRA_CFLAGS="-DNO_CONNTRACK"` to disable it completly. 

If you want to be able to use connbytes in custom stack where conntrack is broken, check #220 and #213 for possible references.

### NAT Hardware/Software offloading

youtubeUnblock will conflict with offloading. But hopefully youtubeUnblock need to process only a bunch of first packets in the connection. So, on some devices it is indeed possible to use youtubeUnblock alongside with offloading, especially on ones driven by nftables (OpenWRT 23+). Note, that this is not tested by me but [reported as a workaround](https://github.com/Waujito/youtubeUnblock/issues/199#issuecomment-2519418553) by users:

Edit `/usr/share/firewall4/templates/ruleset.uc` by replacing
```
meta l4proto { tcp, udp } flow offload @ft;
```
with
```
meta l4proto { tcp, udp } ct original packets ge 30 flow offload @ft;
```

And restart firewall with `service firewall restart`


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

You can configure the module with its flags:

```sh
insmod kyoutubeUnblock.ko 
echo "--fake_sni=1 --exclude_domains=.ru --quic_drop" | sudo tee /sys/module/kyoutubeUnblock/parameters/parameters
```

You can also do 

```sh
cat /sys/module/kyoutubeUnblock/parameters/parameters
```

and check all the parameters configured.

You can check up the statistics of youtubeUnblock with

```sh
sudo cat /proc/kyoutubeUnblock
```

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

**If you got a very large module, you can strip it and significiantly decrese the size:**

```sh
strip --strip-debug kyoutubeUnblock.ko
```

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


## Padavan
YoutubeUnblock may also run on Padavan. [Check the manual here\[rus\]](Padavan.md)

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
  - [How it works:](#how-it-works)
  - [How it processes packets](#how-it-processes-packets)
  - [Compilation](#compilation)
  - [OpenWRT case](#openwrt-case)
    - [Building OpenWRT .ipk package](#building-openwrt-ipk-package)
    - [Building with toolchain](#building-with-toolchain)


# youtubeUnblock

Bypasses Deep Packet Inspection (DPI) systems that relies on SNI. The package is for Linux only. It is also fully compatible with routers running [OpenWRT](https://github.com/openwrt). 

The program was primarily developed to bypass YouTube Outage in Russia.

The program is compatible with routers based on OpenWRT, Entware(Keenetic/ASUS) and host machines. The program offers binaries via Github Actions. The binaries of main branch are published in the [development pre-release](https://github.com/Waujito/youtubeUnblock/releases/tag/continuous). Check out [Github Actions](https://github.com/Waujito/youtubeUnblock/actions/workflows/build-ci.yml) if you want to see all the binaries compiled ever. You should know the arcitecture of your hardware to use binaries. On OpenWRT you can check it with command `grep ARCH /etc/openwrt_release`.

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

Now we are ready to demonize the application.

If you installed package from Github Actions or built it yourself with OpenWRT SDK, rc scripts are preinstalled. All you need is to do `/etc/init.d/youtubeUnblock start`.
Elsewhere copy `owrt/youtubeUnblock.owrt` to `/etc/init.d/youtubeUnblock` and put the program's binary into /usr/bin/. (Don't forget to `chmod +x` both). Now run `/etc/init.d/youtubeUnblock start`. 

You can also run `/etc/init.d/youtubeUnblock enable` to force OpenWRT autostart on boot, but I don't recommend this since if the package has bugs you may lose access to the router (I think you will be able to reset it with reset settings tricks documented for your router). 

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
nft add rule inet fw4 mangle_forward tcp dport 443 ct original "packets < 20" counter queue num 537 bypass
nft insert rule inet fw4 output mark and 0x8000 == 0x8000 counter accept
```

#### Iptables rules

On iptables you should put next iptables rules:
```sh
iptables -t mangle -A FORWARD -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
iptables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT
```

#### IPv6

For IPv6 on iptables you need to duplicate rules above for ip6tables:
```sh
ip6tables -t mangle -A FORWARD -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
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

- `--sni-domains=<comma separated domain list>|all` List of domains you want to be handled by SNI. Use this string if you want to change default domain list. Defaults to `googlevideo.com,ggpht.com,ytimg.com,youtube.com,play.google.com,youtu.be,googleapis.com,googleusercontent.com,gstatic.com,l.google.com`. You can pass **all** if you want for every *ClientHello* to be handled. You can exclude some domains from _all_ with `--exclude-domains` flag.

- `--exclude-domains=<comma separated domain list>` List of domains to be excluded from targetting. Useful if you use `--sni-domains=all` and want for some websites to not be targetted by youtubeUnblock. Also the use case is subdomains (for example if you unblock l.google.com, dl.google.com will be also targetted. You can pass it to this flag and it will be ignored).

- `--queue-num=<number of netfilter queue>` The number of netfilter queue **youtubeUnblock** will be linked to. Defaults to **537**.

- `--fake-sni={0|1}` This flag enables fake-sni which forces **youtubeUnblock** to send at least three packets instead of one with TLS *ClientHello*: Fake *ClientHello*, 1st part of original *ClientHello*, 2nd part of original *ClientHello*. This flag may be related to some Operation not permitted error messages, so before open an issue refer to [Troubleshooting for EPERMS](#troubleshooting-eperms-operation-not-permitted). Defaults to **1**.

- `--fake-sni-seq-len=<length>` This flag specifies **youtubeUnblock** to build a complicated construction of fake client hello packets. length determines how much fakes will be sent. Defaults to **1**.

- `--faking-strategy={randseq|ttl|tcp_check|pastseq}` This flag determines the strategy of fake packets invalidation. Defaults to `randseq`
  - `randseq` specifies that random sequence/acknowledgemend random will be set. This option may be handled by provider which uses *conntrack* with drop on invalid *conntrack* state firewall rule enabled. 
  - `ttl` specifies that packet will be invalidated after `--faking-ttl=n` hops. `ttl` is better but may cause issues if unconfigured. 
  - `pastseq` is like `randseq` but sequence number is not random but references the packet sent in the past (before current).
  - `tcp_check` will invalidate faking packet with invalid checksum. May be handled and dropped by some providers/TSPUs.

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

## How it works:

Let's look from the DPI systems side of view: All of they have an ip and tcp information, higher-level data is encrypted. So from the IP header only IP address might be helpful for them to limit user traffic. In TCP here is basically nothing. So they may handle IP addresses and process it. 

What's wrong? Google servers are on the way: It is very hard to handle all that infrastructure. One server may host multiple websites and it is very bad if them blocks, for example, Google Search while trying to block YouTube (googlevideo). But even if YouTube servers have their own IP for only googlevideo purposes, here is a problem about how large is Google infrastracture and how much servers in it. The DPI systems can't even parse normally all the servers, because each video may live on its cache server [GGC](https://support.google.com/interconnect/answer/9058809?hl=en).

So what's else? Let's take a look at a TLS level. All information here is encrypted. All... Except *ClientHello* messages! They are used to initialize handshake connections and hold tons of helpful information. If we talk about TLS version 1.3, it is optimized to transfer as less information as possible unencrypted. But here is only one thing that may point us which domain the user wants to connect, the SNI extension. It transfers all domain names unencrypted in plain text. Exactly what we need! And DPI systems may use this text to detect YouTube connections and slow down or reject them (In fact they are corrupting a TCP connection with bad packets).

So we aim to somehow hide the SNI from them. How?

- We can alter the SNI name in the tls packet to something else. But what's wrong with this? The server also uses SNI name for certificates (CN=). And if we change it, the server will return an invalid certificate which browser can't normally process, which may turn out to the MITM problem.

- We can encrypt it. Here are a lot of investigations about SNI, but the server should support this technique. Also ISPs may block [encrypted SNI](https://en.wikipedia.org/wiki/Server_Name_Indication).

- So what else can we do with the SNI info? If we can't hide it, let's rely on DPI systems weak spots. The DPI is an extremely high loaded infrastructure that analyzes every single packet sent to the Internet. And every performance-impacted feature should be avoided for them. One of this features is IP packet fragmentation. We can split the packet in the middle of SNI message and post it. For DPI fragmentation involves too much overhead: they should store a very big mapping table which maps IP id, Source ip and Destination ip. Also note that some packets may be lost and DPI should support auto-clean of that table. So just imagine how much memory and CPU time will this cost for DPI. But fragments are ok for clients and hosts. And that's the base idea behind this package. I have to mention here that the idea isn't mine, I get in here after some research for this side. Here already was a solution for Windows, GoodbyeDPI. I just made an alternative for Linux.

You may read further in an [yt-dlp issue page](https://github.com/yt-dlp/yt-dlp/issues/10443) and in [ntc party forum](https://ntc.party/t/%D0%BE%D0%B1%D1%81%D1%83%D0%B6%D0%B4%D0%B5%D0%BD%D0%B8%D0%B5-%D0%B7%D0%B0%D0%BC%D0%B5%D0%B4%D0%BB%D0%B5%D0%BD%D0%B8%D0%B5-youtube-%D0%B2-%D1%80%D0%BE%D1%81%D1%81%D0%B8%D0%B8/8074).

## How it processes packets

When the packet is joining the queue, the application checks SNI payload to be YouTube(googlevideo) (right how the DPI systems do), segmentate/fragmentates (both TCP and IP fragmentation techniques are supported) and posts the packet. Note that it is impossible to post two fragmented packets from one netfilter queue verdict. Instead, the application drops an original packet and makes another linux raw socket to post the packets in the network. To escape infinity loops the socket marks outgoing packets and the application automatically accepts it.

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


 >If you have any questions/suggestions/problems feel free to open an [issue](https://github.com/Waujito/youtubeUnblock/issues).

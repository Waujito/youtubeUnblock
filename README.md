# youtubeUnblock
Bypasses Googlevideo detection systems that relies on SNI. The package is for Linux only. 

For Windows use [GoodbyeDPI from ValdikSS](https://github.com/ValdikSS/GoodbyeDPI) (Users points out that working options for it are `goodbyedpi.exe -6 --frag-by-sni`.) The same behavior is also implemented in [zapret package for linux](https://github.com/bol-van/zapret).

## How it works:
Lets look from the DPIses side of view: All they have is ip and tcp information, higher-level data is encrypted. So from the IP header only IP address might be helpful for them. In tcp here is basically nothing. So they may handle IP addresses and process it. What's wrong? Google servers are on the way: It is very hard to handle all that infrastracture. One server may host multiple websites and it is very bad if them block, say Google Search trying to block googlevideo. But even if googlevideo servers have their own ip for only googlevideo purposes, here is a problem about how large is Google infrastracture and how much servers are here. The DPIs can't even parse normally all the servers, because each video may live on it's cache server. So what's else? Let's take a look at a TLS level. All information here is encrypted. All... Except hello messages! They are used to initialize handshake connections and hold tons of helpful information. If we talk about TLS v1.3, it is optimized to transfer as less information as possible unencrypted. But here is only one thing that may point us which domain the user wants to connect, the SNI extension. It transfers all domain names unencrypted. Exactly what we need! And DPIs may use this thing to detect google video connections and slow down them (In fact they are corrupting a tcp connection with bad packets).

So we aims to somehow hide the SNI from them. How?
- We can alter the SNI name in the tls packet to something else. But what's wrong with this? The server also uses SNI name for certificates. And if we change it, the server will return an invalid certificate which browser can't normally process, which may turn out to the MITM problem.
- We can encrypt it. Here are a lot of investigations about SNI, but the server should support the technique. Also ISPs may block encrypted SNI. [Check this Wikipedia page](https://en.wikipedia.org/wiki/Server_Name_Indication)
- So what else can we do with the SNI info? If we can't hide it, let's rely on DPIs weak spots. The DPI is an extremly high loaded machine that analyzes every single packet sent to the Internet. And every performance-impacted feature should be avoided for them. One of this features is IP packet fragmentation. We can split the packet in the middle of SNI message and post it. For DPI fragmentation involves too much overhead: they should store a very big mapping table which maps IP id, Source ip and Destination ip. Also note that some packets may be lost and DPI should support auto-clean of that table. So just imagine how much memory and CPU time will this cost for DPI. But fragments are ok for clients and hosts. And that's the base idea behind this package. I have to mention here that the idea isn't mine, I get in here after some research for this side. Here already was a solution for Windows, GoodbyeDPI. I just made an alternative for Linux.

You may read further in an [yt-dlp issue page](https://github.com/yt-dlp/yt-dlp/issues/10443) and in [ntc party forum](https://ntc.party/t/%D0%BE%D0%B1%D1%81%D1%83%D0%B6%D0%B4%D0%B5%D0%BD%D0%B8%D0%B5-%D0%B7%D0%B0%D0%BC%D0%B5%D0%B4%D0%BB%D0%B5%D0%BD%D0%B8%D0%B5-youtube-%D0%B2-%D1%80%D0%BE%D1%81%D1%81%D0%B8%D0%B8/8074).

## How it processes packets
When the packet is joining the queue, the application checks sni payload to be googlevideo (right how the DPIs do), segmentates/fragmentates (both TCP and IP fragmentation techniques are supported) and posts the packet. Note that it is impossible to post two fragmented packets from one netfilter queue verdict. Instead, the application drops an original packet and makes another linux raw socket to post the packets in the network. To escape infinity loops the socket marks outgoing packets and the application automatically accepts it.

## Usage:
Before compilation make sure `gcc`, `make`, `autoconf`, `automake`, `pkg-config` and `libtool` is installed. For Fedora `glibc-static` should be installed as well.
Compile with `make`. Install with `make install`. The package include libnetfilter_queue, libnfnetlink and libmnl as static dependencies. The package requires linux-headers and kernel built with netfilter nfqueue support.

You should also configure iptables for this to start working:
```iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass```
Here iptables serves every tcp packet, destinating port 443 for this userspace packet analyzer (via netfilter kernel module) queue-num may be any number from 0 to 65565. --queue-bypass allows traffic to pass if the application is down.

Run an application with `youtubeUnblock 537` where `537` stands for the queue-num (must be the same as in the iptables rule).

Systemd daemon is also available. Do `systemctl enable --now youtubeUnblock.service` after installation (uses queue-num `537`). Please, note that systemd will configure iptables automatically. If you have troubles with it, delete ExecStartPre and ExecStop from youtubeUnblock.service and configure iptables manually (may be a useful case for nftables).

Also DNS over HTTPS (DOH) is preferred for additional anonimity. 

## Troubleshooting
If you have any troubles with youtubeUnblock, here are some options to tune. If them don't work in your case, please, open an issue. You can pass these options in make CFLAGS (`make CFLAGS=...`) or edit CFLAGS variable in Makefile.
Available flags:
- -DUSE_SEG2_DELAY This flag forces youtubeUnblock to wait little bit before send the 2nd part of the split packet. You can tune the amount of time in `#define SEG2_DELAY 100` where 100 stands for milliseconds.
- -DNO_FAKE_SNI This flag forces youtubeUnblock to send at least three packets instead of one with TLS ClientHello: Fake ClientHello, 1st part of original ClientHello, 2nd part of original ClientHello.
- -DNOUSE_GSO This flag disables fix for Google Chrome fat ClientHello. The GSO is well tested now, so this flag probably won't fix anything.

## OpenWRT case
The package is also compatible with routers. The router should be running by free opensource linux-based system such as [OpenWRT](https://openwrt.org/). You should cross-compile it under your host machine. Be ready for compilation errors and a lot of googling about it. It is not such a trivial process! You can get crosscompilation toolsuite compatible with your router from OpenWRT repositories. For example, I have ramips/mt76x8 based router so for me the toolsuite is on https://downloads.openwrt.org/releases/23.05.3/targets/ramips/mt76x8/ and called `openwrt-toolchain-23.05.3-ramips-mt76x8_gcc-12.3.0_musl.Linux-x86_64.tar.xz`. You can find out more about your router model on it's openwrt page. When you download the toolsuite, untar it somewhere. Now we are ready for compilation. My cross gcc asked me to create a staging dir for it and pass it as an environment variable. Also you should notice toolsuite packages and replace my make command with yours. ```STAGING_DIR=temp make CC=/usr/bin/mipsel-openwrt-linux-gcc LD=/usr/bin/mipsel-openwrt-linux-gcc AR=/usr/bin/mipsel-openwrt-linux-ar OBJDUMP=/usr/bin/mipsel-openwrt-linux-objdump NM=/usr/bin/mipsel-openwrt-linux-nm STRIP=/usr/bin/mipsel-openwrt-linux-strip CROSS_COMPILE_PLATFORM=mipsel-buildroot-linux-gnu```. Take a look at `CROSS_COMPILE_PLATFORM` It is required by autotools but I think it is not necessary. Anyways I put `mipsel-buildroot-linux-gnu` in here. For your model may be an [automake cross-compile manual](https://www.gnu.org/software/automake/manual/html_node/Cross_002dCompilation.html) will be helpful. When compilation is done, the binary file will be in build directory. Copy it to your router. Note that an ssh access is likely to be required to proceed. sshfs don't work on my model so I injected the application to the router via Software Upload Package page. It has given me an error, but also a `/tmp/upload.ipk` file which I copied in root directory, `chmod +x`-ed and run.

Now let's talk about a router configuration. I installed a normal iptables user-space app: `xtables-legacy iptables-zz-legacy` and kernel/iptables nfqueue extensions: `iptables-mod-nfqueue kmod-ipt-nfqueue` and add `iptables -t mangle -A FORWARD -p tcp -m tcp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass` rule.

Next step is to daemonize the application in openwrt. Copy youtubeUnblock.owrt to /etc/init.d/youtubeUnblock and put the program into /usr/bin/. (Don't forget to `chmod +x` both). Now run `/etc/init.d/youtubeUnblock start`. You can alo run `/etc/init.d/youtubeUnblock enable` to force OpenWRT autostart the program on boot. 

**If you have any questions/suggestions/problems feel free to open an issue.**

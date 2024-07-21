# youtubeUnblock
Bypasses Googlevideo detection systems that relies on SNI. The package is for Linux only. 

For Windows use [GoodbyeDPI from VladikSS](https://github.com/ValdikSS/GoodbyeDPI) (Users points out that working options for it are `goodbyedpi.exe -6 --frag-by-sni`.) The same behaviour is also implemented in [zapret package for linux](git@github.com:bol-van/zapret.git).

## How it works:
Lets look from the RKN's side of view: All they have is ip and tcp information, higher-level data is encrypted. So from the IP header only IP address might be helpful for them. In tcp here is basically nothing. So they may handle IP addresses and process it. What's wrong? Google servers are on the way: It is very hard to handle all that infrastracture. One server may host multiple websites and it is very bad if them block, say Google Search trying to block googlevideo. But even if googlevideo servers have their own ip for only googlevideo purposes, here is a problem about how large is Google infrastracture and how much servers are here. The RKN can't even parse normally all the servers, because each video may live on it's cache server. So what's else? Let's take a look at a TLS level. All information here is encrypted. All... Except hello messages! They are used to initialize handshake connections and hold tons of helpful information. If we talk about TLS v1.3, it is optimized to transfer as less information as possible unencrypted. But here is only one thing that may point us which domain the user wants to connect, the SNI extension. It transfers all domain names unencrypted. Exactly what we need! And RKN uses this thing to detect google video connections and slow down them (In fact they are corrupting a tcp connection with bad packets).

So we aims to somehow hide the SNI from them. How?
- We can alter the SNI name in the tls packet to something else. But what's wrong with this? The server also uses SNI name for certificates. And if we change it, the server will return an invalid certificate which browser can't normally process, which may turn out to the MITM problem.
- We can encrypt it. Here are a lot of investigations about SNI, but the server should support the technique. Also ISPs may block encrypted SNI. [Check this Wikipedia page](https://en.wikipedia.org/wiki/Server_Name_Indication)
- So what else can we do with the SNI info? If we can't hide it, let's rely on DPIs weak spots. The DPI is an extremly high loaded machine that analyzes every single packet sent to the Internet. And every performance-impacted feature should be avoided for them. One of this features is IP packet fragmentation. We can split the packet in the middle of SNI message and post it. For DPI fragmentation involves too much overhead: they should store a very big mapping table which maps IP id, Source ip and Destination ip. Also note that some packets may be lost and DPI should support auto-clean of that table. So just imagine how much memory and CPU time will this cost for DPI. But fragments are ok for clients and hosts. And that's the base idea behind this package. I have to mention here that the idea isn't mine, I get in here after some research for this side. Here already was a solution for Windows, GoodbyeDPI. I just made an alternative for Linux.

## Usage:
Compile with `make`. The package requires `libnetfilter_queue` library.

You should also configure iptables for this to start working:
```iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 2 --queue-bypass```
Here iptables serves every tcp packet, destinating port 443 for this userspace packet analyzer (via netfilter kernel module) queue-num may be any number from 0 to 65565. --queue-bypass allows traffic to pass if the application is down.

Run an application with `./build/youtubeUnblock 2` where `2` stands for the queue-num (must be the same as in the iptables rule). The daemon service is unavailable now and in **TODO** state.

How it processes packets: When the packet is joining queue, the application checks sni payload to be googlevideo (right how the DPIs do), fragmentates and posts the packet. Note that it is impossible to post two fragmented packets from one netfilter queue verdict. Instead, the application drops an original packet and makes another linux raw socket to post the packets in the network. To escape infinity loops the socket marks outgoing packets and the application automatically accepts it. 

Please note that the application needs in further development. Some googlevideo servers may still be unabailable, some may drop out hello packets on Firefox while some may do so on Chrome. If you got in trouble try to disable GSO (Pass -DNOUSE-GSO as CC_FLAGS). If you have any questions/suggestions feel free to open an issue.

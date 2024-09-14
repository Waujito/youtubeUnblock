local sys = require "luci.sys"
-- local uci = require "luci.model.uci".cursor()
local m = Map("youtubeUnblock", "youtubeUnblock", "Bypasses Deep Packet Inspection (DPI) systems that rely on SNI")
local s = m:section(NamedSection, "youtubeUnblock", "youtubeUnblock", "youtubeUnblock", "Config. Check the README for more details <a href=\"https://github.com/Waujito/youtubeUnblock\">https://github.com/Waujito/youtubeUnblock</a>")

local o
s:option(Flag, "fake_sni", "fake sni", "This flag enables fake-sni which forces youtubeUnblock to send at least three packets instead of one with TLS ClientHello: Fake ClientHello, 1st part of original ClientHello, 2nd part of original ClientHello. This flag may be related to some Operation not permitted error messages, so before open an issue refer to Troubleshooting for EPERMS.")

o = s:option(ListValue, "faking_strategy", "faking strategy", 
	[[
	This flag determines the strategy of fake packets invalidation. 
	<ul style="list-style: disc">
	<li><code>randseq</code> specifies that random sequence/acknowledgemend random will be set. This option may be handled by provider which uses conntrack with drop on invalid conntrack state firewall rule enabled. </li>
	<li><code>ttl</code> specifies that packet will be invalidated after --faking-ttl=n hops. ttl is better but may cause issues if unconfigured. </li>
	<li><code>pastseq</code> is like randseq but sequence number is not random but references the packet sent in the past (before current). </li>
	<li><code>tcp_check</code> will invalidate faking packet with invalid checksum. May be handled and dropped by some providers/TSPUs.</li>
	<li><code>md5sum</code> will invalidate faking packet with invalid TCP md5sum. md5sum is a TCP option which is handled by the destination server but may be skipped by TSPU.</li>
	</ul>
	]])
o:value("pastseq", "pastseq")
o:value("randseq", "randseq")
o:value("ttl", "ttl")
o:value("tcp_check", "tcp_check")
o:value("md5sum", "md5sum")
o.widget="radio"
o:depends("fake_sni", 1)

o = s:option(Value, "faking_ttl", "faking ttl", "Tunes the time to live (TTL) of fake SNI messages. TTL is specified like that the packet will go through the DPI system and captured by it, but will not reach the destination server.")
o:depends("faking_strategy", "ttl")

o = s:option(Value, "fake_seq_offset", "fake seq offset", "Tunes the offset from original sequence number for fake packets. Used by randseq faking strategy. If 0, random sequence number will be set.")
o:depends("faking_strategy", "randseq")

o = s:option(Value, "fake_sni_seq_len", "fake sni seq len", "This flag specifies youtubeUnblock to build a complicated construction of fake client hello packets. length determines how much fakes will be sent.")
o:depends("fake_sni", 1)

o = s:option(ListValue, "frag", "fragmentation strategy", "Specifies the fragmentation strategy for the packet. Tcp is used by default. Ip fragmentation may be blocked by DPI system. None specifies no fragmentation. Probably this won't work, but may be will work for some fake sni strategies.")
o:value("tcp", "tcp")
o:value("ip", "ip")
o:value("none", "none")
o.widget="radio"

o = s:option(Flag, "frag_sni_reverse", "frag sni reverse", "Specifies youtubeUnblock to send ClientHello fragments in the reverse order.")
o:depends("frag", "tcp")
o:depends("frag", "ip")

o = s:option(Flag, "frag_sni_faked", "frag sni faked", "Specifies youtubeUnblock to send fake packets near ClientHello (fills payload with zeroes).")
o:depends("frag", "tcp")
o:depends("frag", "ip")

o = s:option(Flag, "frag_middle_sni", "frag middle sni", "With this options youtubeUnblock will split the packet in the middle of SNI data.")
o:depends("frag", "tcp")
o:depends("frag", "ip")

o = s:option(Value, "frag_sni_pos", "frag sni pos", "With this option youtubeUnblock will split the packet at the position pos.")
o:depends("frag", "tcp")
o:depends("frag", "ip")

o = s:option(Flag, "quic_drop", "drop quic", "Drop all QUIC packets which goes to youtubeUnblock. Won't affect any other UDP packets. Suitable for some TVs. Note, that for this option to work you should also add proxy udp to youtubeUnblock in firewall. connbytes may also be used with udp.")

o = s:option(Value, "fk_winsize", "frag winsize", "Specifies window size for the fragmented TCP packet. Applicable if you want for response to be fragmented. May slowdown connection initialization. Pass 0 if you don't want this.")
o:depends("frag", "tcp")
o:depends("frag", "ip")

o = s:option(Flag, "synfake", "synfake", "If 1, syn payload will be sent before each request. The idea is taken from syndata from zapret project. Syn payload will normally be discarded by endpoint but may be handled by TSPU. This option sends normal fake in that payload. Please note, that the option works for all the sites, so --sni-domains won't change anything.")

o = s:option(Value, "synfake_len", "synfake len", "The fake packet sent in synfake may be too large. If you experience issues, lower up synfake-len. where len stands for how much bytes should be sent as syndata. Pass 0 if you want to send an entire fake packet.")
o:depends("synfake", 1)

o = s:option(Value, "seg2delay", "seg2delay", "This flag forces youtubeUnblock to wait a little bit before send the 2nd part of the split packet.")

o = s:option(Flag, "silent", "silent", "Disables verbose mode")
o:depends("trace", 0)

o = s:option(Flag, "trace", "trace", "Maximum verbosity for debug purposes")
o:depends("silent", 0)

o = s:option(Flag, "no_gso", "no gso", "Disables support for Google Chrome fat packets which uses GSO. This feature is well tested now, so this flag probably won't fix anything.")

o = s:option(Flag, "no_ipv6", "disable ipv6", "Disables support for ipv6. May be useful if you don't want for ipv6 socket to be opened.")

o = s:option(Value, "packet_mark", "packet mark", "Use this option if youtubeUnblock conflicts with other systems rely on packet mark. Note that you may want to change accept rule for iptables to follow the mark.")

o = s:option(Flag, "all_domains", "Target all domains", "Use this option if you want for every ClientHello to be handled")
o = s:option(DynamicList, "sni_domains", "sni domains", "List of domains you want to be handled by SNI.")
o:depends("all_domains", 0)

o = s:option(DynamicList, "exclude_domains", "excluded domains", "List of domains to be excluded from targetting.")

local bs = m:section(NamedSection, "youtubeUnblock", "youtubeUnblock", "Service status")

local asts = sys.call("/etc/init.d/youtubeUnblock enabled &>/dev/null")

if asts == 0 then
	local asto = bs:option(Button, "_autostart_disable", "Autostart")
	asto.inputstyle = "negative"
	asto.inputtitle = "Disable"

	asto.write = function(self, section)
		sys.call("/etc/init.d/youtubeUnblock disable &>/dev/null")
	end
else
	local asto = bs:option(Button, "_autostart_enable", "Autostart")
	asto.inputstyle = "positive"
	asto.inputtitle = "Enable"

	asto.write = function(self, section)
		sys.call("/etc/init.d/youtubeUnblock enable &>/dev/null")
	end
end


local sts = sys.call("/etc/init.d/youtubeUnblock running &>/dev/null")

if sts == 0 then
	local sto = bs:option(Button, "_status_stop", "Status")
	sto.inputstyle = "negative"
	sto.inputtitle = "Stop"
	sto.description = "youtubeUnblock is currently active"

	sto.write = function(self, section)
		sys.call("/etc/init.d/youtubeUnblock stop &>/dev/null")
	end
else
	local sto = bs:option(Button, "_status_start", "Status")
	sto.inputstyle = "positive"
	sto.inputtitle = "Start"
	sto.description = "youtubeUnblock is currently down"

	sto.write = function(self, section)
		sys.call("/etc/init.d/youtubeUnblock start &>/dev/null")
	end
end

local rso = bs:option(Button, "_restart", "Restart")
rso.inputstyle = "action"
function rso.write(self, section)
	sys.call("/etc/init.d/youtubeUnblock restart &>/dev/null")
end

local fwo = bs:option(Button, "_firewall", "Firewall")
fwo.inputtitle = "Reload"
fwo.inputstyle = "action"
function fwo.write(self, section)
	sys.call("/etc/init.d/firewall reload")
end

local logs = sys.exec("logread -l 800 -p youtubeUnblock | grep youtubeUnblock | sed '1!G;h;$!d'")
local o = bs:option(DummyValue, "_logs", "Logs")
o.rawhtml = true
o.value = logs
o.wrap = "off"
o.rows = 33
o.readonly = true
o.template = "cbi/tvalue"
o.width = "100%"

return m

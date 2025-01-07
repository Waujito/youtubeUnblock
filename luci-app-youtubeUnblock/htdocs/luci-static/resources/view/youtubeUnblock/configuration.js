'use strict';
'require view';
'require poll';
'require fs';
'require ui';
'require uci';
'require form';
'require tools.widgets as widgets';

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('youtubeUnblock'),
		]);
	},

	renderSectionTLSConfigs: function(s) {
		let o;

		o = s.option(form.Flag, "tls_enabled", _("TLS enabled"), _("Disable this flag if you want not to process TLS traffic in current section. May be used if you want to set only UDP-based policy."));
		o.enabled = '1';
		o.disabled = '0';
		o.default = o.enabled;
		o.rmempty = false;


		o = s.option(form.Flag, "fake_sni", _("Fake sni"), _("This flag enables fake-sni which forces youtubeUnblock to send at least three packets instead of one with TLS ClientHello: Fake ClientHello, 1st part of original ClientHello, 2nd part of original ClientHello. This flag may be related to some Operation not permitted error messages, so before open an issue refer to Troubleshooting for EPERMS."));
		o.depends('tls_enabled', '1');
		o.enabled = '1'
		o.disabled = '0'
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.ListValue, "faking_strategy", _("Faking strategy"), `
			This flag determines the strategy of fake packets invalidation. 
			<ul style="list-style: disc">
			<li><code>randseq</code> specifies that random sequence/acknowledgment random will be set. This option may be handled by provider which uses conntrack with drop on invalid conntrack state firewall rule enabled. </li>
			<li><code>ttl</code> specifies that packet will be invalidated after --faking-ttl=n hops. ttl is better but may cause issues if unconfigured. </li>
			<li><code>pastseq</code> is like randseq but sequence number is not random but references the packet sent in the past (before current). </li>
			<li><code>tcp_check</code> will invalidate faking packet with invalid checksum. May be handled and dropped by some providers/TSPUs.</li>
			<li><code>md5sum</code> will invalidate faking packet with invalid TCP md5sum. md5sum is a TCP option which is handled by the destination server but may be skipped by TSPU.</li>
			</ul>`
		);
		o.depends("fake_sni", '1');
		o.widget="radio";
		o.value("pastseq", "pastseq");
		o.value("randseq", "randseq");
		o.value("ttl", "ttl");
		o.value("tcp_check", "tcp_check");
		o.value("md5sum", "md5sum");
		o.default = "pastseq";
		o.rmempty = false;

		o = s.option(form.Value, "faking_ttl", _("Faking ttl"), _("Tunes the time to live (TTL) of fake SNI messages. TTL is specified like that the packet will go through the DPI system and captured by it, but will not reach the destination server."));
		o.depends("faking_strategy", "ttl");
		o.default = 8;
		o.rmempty = false;

		o = s.option(form.Value, "fake_seq_offset", _("Fake seq offset"), _("Tunes the offset from original sequence number for fake packets. Used by randseq faking strategy. If 0, random sequence number will be set."));
		o.depends("faking_strategy", "randseq");
		o.default = 10000;
		o.rmempty = false;

		o = s.option(form.Value, "fake_sni_seq_len", _("Fake sni seq len"), _("This flag specifies youtubeUnblock to build a complicated construction of fake client hello packets. length determines how much fakes will be sent."));
		o.depends("fake_sni", "1")
		o.default = 1;
		o.rmempty = false;

		o = s.option(form.ListValue, "fake_sni_type", _("Fake sni type"), _("This flag specifies which faking message type should be used for fake packets. For random, the message of the random length and with random payload will be sent. For default the default payload (sni=www.google.com) is used. And for the custom option, the payload from --fake-custom-payload section utilized. Defaults to <code>default</code>."));
		o.depends("fake_sni", "1");
		o.widget="radio";
		o.value("default", "default");
		o.value("custom", "custom");
		o.value("random", "random");
		o.default = "default";
		o.rmempty = false;

		o = s.option(form.Value, "fake_custom_payload", _("Fake custom payload"), _("Useful with --fake-sni-type=custom. You should specify the payload for fake message manually. Use hex format: --fake-custom-payload=0001020304 mean that 5 bytes sequence: 0x00, 0x01, 0x02, 0x03, 0x04 used as fake."));
		o.depends("fake_sni_type", "custom");

		o = s.option(form.ListValue, "frag", _("Fragmentation strategy"), _("Specifies the fragmentation strategy for the packet. Tcp is used by default. Ip fragmentation may be blocked by DPI system. None specifies no fragmentation. Probably this won't work, but may be will work for some fake sni strategies."));
		o.depends('tls_enabled', '1');
		o.widget="radio";
		o.value("tcp", "tcp");
		o.value("ip", "ip");
		o.value("none", "none");
		o.default = "tcp";
		o.rmempty = false;

		o = s.option(form.Flag, "frag_sni_reverse", _("Frag sni reverse"), _("Specifies youtubeUnblock to send ClientHello fragments in the reverse order."));
		o.depends("frag", "tcp");
		o.depends("frag", "ip");
		o.enabled = '1'
		o.disabled = '0'
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.Flag, "frag_sni_faked", _("Frag sni faked"), _("Specifies youtubeUnblock to send fake packets near ClientHello (fills payload with zeroes)."));
		o.depends("frag", "tcp");
		o.depends("frag", "ip");
		o.enabled = '1'
		o.disabled = '0'
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.Flag, "frag_middle_sni", _("Frag middle sni"), _("With this options youtubeUnblock will split the packet in the middle of SNI data."));
		o.depends("frag", "tcp");
		o.depends("frag", "ip");
		o.enabled = '1'
		o.disabled = '0'
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.Value, "frag_sni_pos", _("Frag sni pos"), _("With this option youtubeUnblock will split the packet at the position pos."));
		o.depends("frag", "tcp");
		o.depends("frag", "ip");
		o.rmempty = false;
		o.default = 1;

		o = s.option(form.Value, "seg2delay", _("seg2delay"), _("This flag forces youtubeUnblock to wait a little bit before send the 2nd part of the split packet."));
		o.depends('tls_enabled', '1');
		o.default = 0;

		o = s.option(form.Value, "fk_winsize", _("Fragmentation winsize"), _("Specifies window size for the fragmented TCP packet. Applicable if you want for response to be fragmented. May slowdown connection initialization. Pass 0 if you don't want this."));
		o.depends("frag", "tcp");
		o.depends("frag", "ip");
		o.default = 0;
		o.rmempty = false;
		
		o = s.option(form.Flag, "synfake", _("Synfake"), _("If 1, syn payload will be sent before each request. The idea is taken from syndata from zapret project. Syn payload will normally be discarded by endpoint but may be handled by TSPU. This option sends normal fake in that payload. Please note, that the option works for all the sites, so --sni-domains won't change anything."));
		o.depends('tls_enabled', '1');
		o.enabled = "1";
		o.disabled = "0";
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.Value, "synfake_len", _("synfake len"), _("The fake packet sent in synfake may be too large. If you experience issues, lower up synfake-len. where len stands for how much bytes should be sent as syndata. Pass 0 if you want to send an entire fake packet."));
		o.depends("synfake", "1");
		o.default = 0;
		o.rmempty = false;	
	},
	renderSectionUDPConfigs: function(s) {
		let o;

		o = s.option(form.Flag, "quic_drop", _("QUIC drop"), _("Drop all QUIC packets which goes to youtubeUnblock. Won't affect any other UDP packets."));
		o.enabled = '1'
		o.disabled = '0'
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.ListValue, "udp_mode", _("UDP mode"), _("Faking strategy for udp. <code>checksum</code> will fake UDP checksum, <code>ttl</code> won't fake but will make UDP content relatively small, <code>none</code> is no faking."));
		o.widget = "radio"
		o.depends("quic_drop", "0");
		o.value("fake", "fake");
		o.value("drop", "drop");
		o.default = "fake";
		o.rmempty = false;

		o = s.option(form.ListValue, "udp_faking_strategy", _("UDP faking strategy"), _("This flag specifies udp handling strategy. If drop udp packets will be dropped (useful for quic when browser can fallback to tcp), if fake udp will be faked."));
		o.widget = "radio"
		o.depends("quic_drop", "0");
		o.value("none", "none");
		o.value("checksum", "checksum");
		o.value("ttl", "ttl");
		o.default = "none";
		o.rmempty = false;


		o = s.option(form.Value, "udp_fake_seq_len", _("UDP fake seq length"), _("Specifies how much faking packets will be sent over the network."));
		o.depends("udp_mode", "fake");
		o.default = 6
		o.rmempty = false;

		o = s.option(form.Value, "udp_fake_len", _("UDP fake length"), _("Size of udp fake payload (typically payload is zeroes)."));
		o.depends("udp_mode", "fake");
		o.default = 64
		o.rmempty = false;

		o = s.option(form.DynamicList, "udp_dport_filter", _("UDP dport filter"), _("Filter the UDP destination ports. Specifie the ports you want to be handled by youtubeUnblock. Valid inputs are port number or port range (e.g. 200-500)."));
		o.depends("quic_drop", "0");

		o = s.option(form.ListValue, "udp_filter_quic", _("UDP QUIC filter"), _("Enables QUIC filtering for UDP handler. If disabled, quic won't be processed, if all, all quic initial packets will be handled."));
		o.widget = "radio"
		o.depends("quic_drop", "0");
		o.value("disabled", "disabled");
		o.value("all", "all");
		o.default = "disabled";
		o.rmempty = false;

	},
	renderDomainConfigs: function(s) {
		let o;

		o = s.option(form.Flag, "all_domains", _("Target all domains"), _("Use this option if you want for every ClientHello to be handled"));
		o.enabled = "1";
		o.disabled = "0";
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.DynamicList, "sni_domains", _("Sni domains"), _("List of domains you want to be handled by SNI."));
		o.depends("all_domains", "0");
		o.default = ["googlevideo.com", "ggpht.com", "ytimg.com", "youtube.com", "play.google.com", "youtu.be", "googleapis.com", "googleusercontent.com", "gstatic.com", "l.google.com"];


		o = s.option(form.DynamicList, "exclude_domains", _("Excluded domains"), _("List of domains to be excluded from targeting."));


		o = s.option(form.ListValue, "sni_detection", _("SNI detection"), _("Specifies how to detect SNI. Parse will normally detect it by parsing the Client Hello message. Brute will go through the entire message and check possibility of SNI occurrence. Please note, that when --sni-domains option is not all brute will be O(nm) time complexity where n stands for length of the message and m is number of domains."));
		o.widget="radio";
		o.value("parse", "parse");
		o.value("brute", "brute");
		o.default = "parse";
	},
	renderGeneralConfigs: function(s) {
		let o;

		o = s.option(form.Flag, "silent", _("Silent"), _("Disables verbose mode"));
		o.defalt = "0"
		o.depends("trace", "0");

		o = s.option(form.Flag, "trace", _("Trace"), _("Maximum verbosity for debug purposes"));
		o.defalt = "0"
		o.depends("silent", "0");

		o = s.option(form.Flag, "no_gso", _("No gso"), _("Disables support for Google Chrome fat packets which uses GSO. This feature is well tested now, so this flag probably won't fix anything."));

		o = s.option(form.Flag, "no_ipv6", _("Disable ipv6"), _("Disables support for ipv6. May be useful if you don't want for ipv6 socket to be opened."));

		o = s.option(form.Value, "packet_mark", _("Packet mark"), _("Use this option if youtubeUnblock conflicts with other systems rely on packet mark. Note that you may want to change accept rule for iptables to follow the mark."));
		o = s.option(form.Value, "post_args", _("Post args"), _("Anything you pass here will be passed to youtubeUnblock as raw args"));
	},

	render: function(result) {
		let m, s, o;

		m = new form.Map('youtubeUnblock', _('youtubeUnblock - Configuration'), _("Check the README for more details <a href=\"https://github.com/Waujito/youtubeUnblock\">https://github.com/Waujito/youtubeUnblock</a>"));

		const general_section = m.section(form.NamedSection, "youtubeUnblock", "youtubeUnblock");
		o = general_section.option(form.ListValue, "conf_strat", _("Configuration strategy"), _("Select to configure youtubeUnblock with plain arguments or with interactive flags"));
		o.widget = "radio";
		o.value("args");
		o.value("ui_flags");
		o.default = "ui_flags";
		o.rmempty = false; 

		o = general_section.option(form.TextValue, "args", "args", "Pass your list of arguments here.");
		o.depends("conf_strat", "args");

		o = general_section.option(form.SectionValue, "_flags_section", 
			form.NamedSection, "youtubeUnblock", "youtubeUnblock", _("UI Flags configuration"));
		o.depends("conf_strat", "ui_flags");

		const flags_section = o.subsection;
		this.renderGeneralConfigs(flags_section);

		o = flags_section.option(form.SectionValue, "_subsections_section", form.GridSection, "section", _("Section configs"), _("Note that sections will be executed in reverse order: from last section to first. After section handles the packet, it stops processing in the next sections"))
		const subsects_section = o.subsection;
		subsects_section.addremove = true;
		subsects_section.anonymous = true;
		subsects_section.sortable  = true;
		subsects_section.cloneable = true;

		subsects_section.sectiontitle = function(section_id) {
			return uci.get('youtubeUnblock', section_id, 'name') || _('Unnamed section');
		};

		o = subsects_section.option(form.Flag, "enabled", _("Enabled"));
		o.enabled = '1';
		o.disabled = '0';
		o.default = '1';
		o.modalonly = false;
		o.editable = true;
		o.rmempty = false;

		subsects_section.tab('general', _("General"));

		o = subsects_section.taboption('general', form.Value, "name", _("Name"));
		o.placeholder = _('Unnamed section');
		o.modalonly = true;


		o = subsects_section.taboption('general', form.Value, "section_post_args", _("Section post args"), _("Section-specific post arguments"));
		o.modalonly = true;

		
		this.renderSectionTLSConfigs({option(optionclass, ...classargs) {
			const o = subsects_section.taboption('general', optionclass, ...classargs);
			o.modalonly = true;
			return o;
		}});

		subsects_section.tab('domains', _("Domains"));
		this.renderDomainConfigs({option(optionclass, ...classargs) {
			const o = subsects_section.taboption('domains', optionclass, ...classargs);
			o.modalonly = true;
			return o;
		}});
		
		subsects_section.tab('udp', _("UDP"));
		this.renderSectionUDPConfigs({option(optionclass, ...classargs) {
			const o = subsects_section.taboption('udp', optionclass, ...classargs);
			o.modalonly = true;
			return o;
		}});

		return m.render();
	}
});

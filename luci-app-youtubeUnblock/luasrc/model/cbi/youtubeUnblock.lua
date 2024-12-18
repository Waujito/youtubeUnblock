local sys = require "luci.sys"
-- local uci = require "luci.model.uci".cursor()
local m = Map("youtubeUnblock", "youtubeUnblock", "Bypasses Deep Packet Inspection (DPI) systems that rely on SNI")
local s = m:section(NamedSection, "youtubeUnblock", "youtubeUnblock", "youtubeUnblock", "Config. Check the README for more details <a href=\"https://github.com/Waujito/youtubeUnblock\">https://github.com/Waujito/youtubeUnblock</a>")

local o
o = s:option(TextValue, "args", "args", "Pass your list of arguments here.")

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

local rso = bs:option(Button, "_reset_settings", "Reset settings to defaults")
rso.inputtitle = "Reset"
rso.inputstyle = "negative"
function rso.write(self, section)
	sys.call("/usr/share/youtubeUnblock/youtubeUnblock_defaults.sh --force")
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

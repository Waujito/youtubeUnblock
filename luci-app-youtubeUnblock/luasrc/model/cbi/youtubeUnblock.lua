local sys = require "luci.sys"
local redirect_path = luci.dispatcher.build_url(
        "admin", "services", "youtubeUnblock"
)

-- local uci = require "luci.model.uci".cursor()
local m = Map("youtubeUnblock", "youtubeUnblock", "Bypasses Deep Packet Inspection (DPI) systems that rely on SNI")
local s = m:section(NamedSection, "youtubeUnblock", "youtubeUnblock", "youtubeUnblock", "Config. Check the README for more details <a href=\"https://github.com/Waujito/youtubeUnblock\">https://github.com/Waujito/youtubeUnblock</a>")

local o = s:option(TextValue, "args", "args", "Pass your list of arguments here.")

s = m:section(NamedSection, "youtubeUnblock", "youtubeUnblock", "Service status")

o = s:option(Button, "_autostart", "Autostart")
o._state = false
function o.cbid(self, section)
	local service_enabled = sys.call("/etc/init.d/youtubeUnblock enabled &>/dev/null")
	self._state = tonumber(service_enabled) == 1
	self.option = self._state and "disabled" or "enabled"
	return AbstractValue.cbid(self, section)
end
function o.cfgvalue(self, section)
	self.title = self._state and "Enable" or "Disable"
	self.inputstyle = self._state and "positive" or "negative"
	self.description = "youtubeUnblock is currently " .. self.option
end
function o.write(self, section)
	if self._state then
		sys.call("/etc/init.d/youtubeUnblock enable &>/dev/null")
	else
		sys.call("/etc/init.d/youtubeUnblock disable &>/dev/null")
	end
	luci.http.redirect(redirect_path)
end

o = s:option(Button, "_status", "Autostart")
o._state = false
function o.cbid(self, section)
	local service_running = sys.call("/etc/init.d/youtubeUnblock running &>/dev/null")
	self._state = tonumber(service_running) == 1
	self.option = self._state and "down" or "active"
	return AbstractValue.cbid(self, section)
end
function o.cfgvalue(self, section)
	self.title = self._state and "Start" or "Stop"
	self.inputstyle = self._state and "positive" or "negative"
	self.description = "youtubeUnblock is currently " .. self.option
end
function o.write(self, section)
	if self._state then
		sys.call("/etc/init.d/youtubeUnblock start &>/dev/null")
	else
		sys.call("/etc/init.d/youtubeUnblock stop &>/dev/null")
	end
	luci.http.redirect(redirect_path)
end

local o = s:option(Button, "_restart", "Restart")
o.inputstyle = "action"
function o.write(self, section)
	sys.call("/etc/init.d/youtubeUnblock restart &>/dev/null")
	luci.http.redirect(redirect_path)
end

local o = s:option(Button, "_firewall", "Firewall")
o.inputtitle = "Reload"
o.inputstyle = "action"
function o.write(self, section)
	sys.call("/etc/init.d/firewall reload")
	luci.http.redirect(redirect_path)
end

local o = s:option(Button, "_reset_settings", "Reset settings to defaults")
o.inputtitle = "Reset"
o.inputstyle = "negative"
function o.write(self, section)
	sys.call("/usr/share/youtubeUnblock/youtubeUnblock_defaults.sh --force")
	luci.http.redirect(redirect_path)
end

s = m:section(NamedSection, "youtubeUnblock", "youtubeUnblock", "Service logs")

local o = s:option(Button, "_reload_logs", "Reload")
o.inputstyle = "reload"
o.inputtitle = "Reload logs"
o.redirect = redirect_path .. "#" .. AbstractValue.cbid(o, "youtubeUnblock")
function o.write(self, section)
        luci.http.redirect(self.redirect)
end

local logs_opt = s:option(DummyValue, "_logs", "Logs")
logs_opt.rawhtml = true
logs_opt.wrap = "off"
logs_opt.rows = 33
logs_opt.readonly = true
logs_opt.template = "cbi/tvalue"
logs_opt.width = "100%"

function logs_opt.cbid(self, section)
	local logs = sys.exec("logread -l 800 -p youtubeUnblock | grep youtubeUnblock | sed '1!G;h;$!d'")
	self.value = logs
	return AbstractValue.cbid(self, section)
end

return m

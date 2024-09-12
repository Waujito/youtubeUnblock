module("luci.controller.youtubeUnblock", package.seeall)

function index()
	entry( {"admin", "services", "youtubeUnblock"}, cbi("youtubeUnblock"), _("youtubeUnblock"))
end

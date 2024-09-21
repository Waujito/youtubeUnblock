#!/bin/sh
[ "$table" != "mangle" ] && exit 0

if [[ "$type" == "ip6tables" ]]; then
/opt/etc/init.d/youtubeUnblock firewall_stop_v6 &>/dev/null || true
/opt/etc/init.d/youtubeUnblock firewall_start_v6 &>/dev/null || true
else
/opt/etc/init.d/youtubeUnblock firewall_stop_v4 &>/dev/null || true
/opt/etc/init.d/youtubeUnblock firewall_start_v4 &>/dev/null ||true
fi

#!/bin/sh
[ "$type" == "ip6tables" ] && exit 0 >/dev/null 2>&1
[ "$table" != "mangle" ] && exit 0 >/dev/null 2>&1
/opt/etc/init.d/S91youtubeUnblock firewall-stop >/dev/null 2>&1
/opt/etc/init.d/S91youtubeUnblock firewall-load >/dev/null 2>&1


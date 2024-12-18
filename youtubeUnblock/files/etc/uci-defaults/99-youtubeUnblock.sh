#!/bin/sh
[[ ! "$(uci -q get youtubeUnblock.youtubeUnblock)" == "" ]] && [[ ! "$1" == "--force" ]] && exit 0
[[ ! "$(uci -q get youtubeUnblock.youtubeUnblock)" == "" ]] && uci delete youtubeUnblock.youtubeUnblock

touch /etc/config/youtubeUnblock
uci batch << EOI
set youtubeUnblock.youtubeUnblock='youtubeUnblock'
set youtubeUnblock.youtubeUnblock.args=''
EOI
uci commit

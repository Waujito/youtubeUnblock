#!/bin/sh

# youtubeUnblock.youtubeUnblock.frag is used to automatically update old configuration to new one.

if [ "$1" != "--force" ] \
	&& [ -z "$(uci -q get youtubeUnblock.youtubeUnblock.frag)" ] \
	&& [ -n "$(uci -q get youtubeUnblock.youtubeUnblock)" ]; then
	exit 0
fi

while uci -q delete youtubeUnblock.@section[0]; do :; done
uci -q delete youtubeUnblock.youtubeUnblock

touch /etc/config/youtubeUnblock
uci batch << EOI
set youtubeUnblock.youtubeUnblock=youtubeUnblock
set youtubeUnblock.youtubeUnblock.conf_strat='ui_flags'
set youtubeUnblock.youtubeUnblock.packet_mark='32768'
set youtubeUnblock.youtubeUnblock.queue_num='537'

add youtubeUnblock section
set youtubeUnblock.@section[0].name='Default section'
set youtubeUnblock.@section[0].enabled='1'
set youtubeUnblock.@section[0].tls_enabled='1'
set youtubeUnblock.@section[0].fake_sni='0'
set youtubeUnblock.@section[0].faking_strategy='pastseq'
set youtubeUnblock.@section[0].fake_sni_seq_len='1'
set youtubeUnblock.@section[0].fake_sni_type='default'
set youtubeUnblock.@section[0].frag='tcp'
set youtubeUnblock.@section[0].frag_sni_reverse='1'
set youtubeUnblock.@section[0].frag_sni_faked='0'
set youtubeUnblock.@section[0].frag_middle_sni='1'
set youtubeUnblock.@section[0].frag_sni_pos='1'
set youtubeUnblock.@section[0].seg2delay='0'
set youtubeUnblock.@section[0].fk_winsize='0'
set youtubeUnblock.@section[0].synfake='0'
set youtubeUnblock.@section[0].sni_detection='parse'
set youtubeUnblock.@section[0].all_domains='0'
add_list youtubeUnblock.@section[0].sni_domains='googlevideo.com' 
add_list youtubeUnblock.@section[0].sni_domains='ggpht.com' 
add_list youtubeUnblock.@section[0].sni_domains='ytimg.com' 
add_list youtubeUnblock.@section[0].sni_domains='youtube.com' 
add_list youtubeUnblock.@section[0].sni_domains='play.google.com' 
add_list youtubeUnblock.@section[0].sni_domains='youtu.be' 
add_list youtubeUnblock.@section[0].sni_domains='googleapis.com' 
add_list youtubeUnblock.@section[0].sni_domains='googleusercontent.com' 
add_list youtubeUnblock.@section[0].sni_domains='gstatic.com' 
add_list youtubeUnblock.@section[0].sni_domains='l.google.com'
set youtubeUnblock.@section[0].quic_drop='0'
set youtubeUnblock.@section[0].udp_mode='fake'
set youtubeUnblock.@section[0].udp_fake_seq_len='6'
set youtubeUnblock.@section[0].udp_fake_len='64'
set youtubeUnblock.@section[0].udp_filter_quic='disabled'
set youtubeUnblock.@section[0].udp_faking_strategy='none'
EOI
uci commit

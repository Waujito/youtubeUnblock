obj-m := kyoutubeUnblock.o
kyoutubeUnblock-objs := src/kytunblock.o src/mangle.o src/quic.o src/quic_crypto.o src/utils.o src/tls.o src/getopt.o src/inet_ntop.o src/args.o src/trie.o deps/cyclone/aes.o deps/cyclone/cpu_endian.o deps/cyclone/ecb.o deps/cyclone/gcm.o deps/cyclone/hkdf.o deps/cyclone/hmac.o deps/cyclone/sha256.o
ccflags-y := -std=gnu99 -DKERNEL_SPACE -Wno-error -Wno-declaration-after-statement -I$(src)/src -I$(src)/deps/cyclone/include

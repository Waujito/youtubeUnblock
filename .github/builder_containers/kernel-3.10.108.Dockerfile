FROM ubuntu:16.04

RUN apt update && apt install -y build-essential flex bc bison libelf-dev elfutils libssl-dev wget

RUN wget https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-3.10.108.tar.xz -O kernel.tar.xz
RUN tar -xf kernel.tar.xz
RUN rm -f kernel.tar.xz
RUN /bin/bash -c "mv linux-* linux"

WORKDIR /linux
RUN make defconfig
RUN make -j$(nproc)

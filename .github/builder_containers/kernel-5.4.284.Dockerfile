FROM ubuntu:24.04

RUN apt update && apt install -y build-essential flex bc bison libelf-dev elfutils libssl-dev wget

RUN wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.4.284.tar.xz -O kernel.tar.xz
RUN tar -xf kernel.tar.xz
RUN rm -f kernel.tar.xz
RUN /bin/bash -c "mv linux-* linux"

WORKDIR /linux
RUN make defconfig
RUN make -j$(nproc)

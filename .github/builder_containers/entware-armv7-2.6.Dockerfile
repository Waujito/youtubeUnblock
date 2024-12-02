FROM waujito/entware_builder
RUN git clone --depth 1 https://github.com/Entware/Entware.git -b k2.6
WORKDIR /home/me/Entware
RUN make package/symlinks
RUN cp -v configs/armv7-2.6.config .config
RUN make -j$(nproc) toolchain/install

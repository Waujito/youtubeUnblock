FROM waujito/entware_builder
RUN git clone --depth 1 https://github.com/Entware/Entware.git
WORKDIR /home/me/Entware
RUN make package/symlinks
RUN cp -v configs/armv7-3.2.config .config
RUN make -j$(nproc) toolchain/install

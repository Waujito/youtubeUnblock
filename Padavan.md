
## Asus-Padavan
На падаване есть раздел, доступный для записи, и докинув нужные модули, можно запустить youtubeUblock на уже установленной прошивке без USB
<br />


<details open>
<summary><b>Установка и настройка</b></summary>

Далее все комадны можно выполнять в консоли админки Administration -> Console или зайти на роутер через SSH
```sh
cd /etc/storage/
```

Сборка бинарника есть ниже, но можно взять готовый
```sh
wget -qO- https://github.com/renr4/misc/raw/refs/heads/main/youtubeUnblock.tar.gz | tar xvz -C /etc/storage/
```

Ниже есть инструкция по сборке прошивки с NFQUEUE модулями, но также проще взять уже готовые
```sh
wget -qO- https://github.com/renr4/misc/raw/refs/heads/main/padavan-nfqueue.tar.gz | tar xvz -C /etc/storage/
```

##### **[1]** Загружаем модули
```sh
insmod /etc/storage/nfnetlink.ko
insmod /etc/storage/nfnetlink_queue.ko
insmod /etc/storage/xt_connbytes.ko
insmod /etc/storage/xt_NFQUEUE.ko
```

##### **[2]** Правила iptables
```sh
iptables -I OUTPUT -m mark --mark 32768/32768 -j ACCEPT
```
Команда с учетом connbytes не поместится в консоли, просто обрежется, в таком случае в консоли можно запустить укороченную версию
```sh
iptables -t mangle -A FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 537 --queue-bypass
```
, а в скрипт добавить полную
```sh
iptables -t mangle -A FORWARD -p tcp --dport 443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 0:19 -j NFQUEUE --queue-num 537 --queue-bypass
```

Если появляется ошибка `iptables: unknown option "--queue-num"`, то можно взять бинарник iptables уже с поддержкой queue-num
```sh
wget -qO- https://github.com/renr4/misc/raw/refs/heads/main/iptables-nfqueue.tar.gz | tar xvz -C /etc/storage/
```
и снова запустить первую команду, добавив к ней абсолютный путь `/etc/storage/iptables -t mangle...`


##### **[3]** Запуск
```sh
/etc/storage/youtubeUnblock 537 --no-ipv6 &
```

На этом этапе все должно работать. Можно проверить на конечном устройстве
```sh
curl --connect-to ::speedtest.selectel.ru https://manifest.googlevideo.com/100MB -k -o/dev/null
```
Только сейчас с такими параметрами ютуб может не заработать (см. https://github.com/Waujito/youtubeUnblock/issues/148)

Сохранение изменений + автозапуск
В админке Customization -> Scripts добавить код из **[1]** и **[3]** в скрипт Run After Router Started, а две команды iptables из **[2]** в скрипт Run After Firewall Rules Restarted и нажать Apply

##### Как обновлять
Закинув новую версию в `/etc/storage/` нужно сделать Administration -> Settings -> Commit Internal Storage to Flash Memory и перезагрузить роутер

##### Как удалить
Проще всего сделать сброс Administration -> Settings -> Router Internal Storage -> Reset и перезагрузить роутер, тогда и скрипты и storage вернутся в исходное состояние
</details>
<br />


<details>
<summary><b>Сборка</b></summary>

```sh
git clone https://gitlab.com/hadzhioglu/padavan-ng
git clone https://github.com/Waujito/youtubeUnblock
```
Готовый тулчейн
```sh
wget -qO- https://gitlab.com/hadzhioglu/padavan-ng/-/package_files/152707964/download | tar xv --zstd -C padavan-ng
export PATH=$PATH:`pwd`/padavan-ng/toolchain/out/bin
```
Патч для ядра 3.4
```sh
cd youtubeUnblock
wget https://raw.githubusercontent.com/renr4/misc/refs/heads/main/patch-padavan-kernel-3.4.diff
patch youtubeUnblock.c < patch-padavan-kernel-3.4.diff
```
Сборка
```sh
make CC=mipsel-linux-uclibc-gcc LD=mipsel-linux-uclibc-ld CROSS_COMPILE_PLATFORM=mipsel-linux-uclibc ARCH=mips 
mipsel-linux-uclibc-strip --strip-unneeded build/youtubeUnblock
```
Закинуть бинарник на роутер можно запустив локально веб-сервер и забрав его в консоли админки wget-ом `wget http://192.168.0.101/youtubeUnblock -P /etc/storage` или, если есть ssh `scp youtubeUnblock admin@192.168.0.1:/etc/storage`
</details>
<br />


<details>
<summary><b>Сборка прошивки с модулями</b></summary>

Если хочется собрать прошивку уже с поддержкой NFQUEUE

Раскомментировать модули в `padavan-ng/trunk/configs/boards/TPLINK/TL_C5-V4/kernel-3.4.x.config`
(вместо TPLINK/TL_C5-V4 нужно выбрать свою модель)
```sh
CONFIG_NETFILTER_XT_TARGET_NFQUEUE=m
CONFIG_NETFILTER_NETLINK_QUEUE=m
CONFIG_IP_NF_QUEUE=m
```

Сборка с нужным конфигом
```sh
cd padavan-ng/trunk
cp configs/templates/tplink/tl_c5-v4.config .config
./build_firmware.sh
```
Если финальный размер превышает лимит, то можно отключить что-нибудь в .config, например FTP

После все сделать как в инструкции по установке выше, закинув youtubeUnblock в /etc/storage/
</details>



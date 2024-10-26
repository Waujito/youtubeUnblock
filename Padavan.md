## Padavan
На падаване есть раздел, доступный для записи (/etc/storage), и, докинув нужные модули, можно запустить youtubeUblock на уже установленной прошивке без USB. Установка самого youtubeUblock мало будет отличаться от классичкской установки. Наибольшая сложность заключается в получении модулей ядра специально для вашего роутера. 

**Версия youtubeUblock должна быть не меньше v1.0.0-rc4.**

### Сборка прошивки с модулями

Необходимо собрать ядро с модулями nfqueue. Собирать можно у себя локально, а можно и в github actions (https://github.com/shvchk/padavan-builder-workflow)

Добавить строки ниже в `padavan-ng/trunk/configs/boards/TPLINK/TL_C5-V4/kernel-3.4.x.config` (вместо TPLINK/TL_C5-V4 нужно выбрать свою модель):

```sh
CONFIG_NETFILTER_NETLINK=m
CONFIG_NETFILTER_NETLINK_QUEUE=m
CONFIG_NETFILTER_XT_TARGET_NFQUEUE=m
CONFIG_IP_NF_QUEUE=m
CONFIG_IP6_NF_QUEUE=m
```

Сборка
```sh
cd padavan-ng/trunk
cp configs/templates/tplink/tl_c5-v4.config .config
./build_firmware.sh
```
Если финальный размер превышает максимум, то можно отключить что-нибудь в .config, например FTP.

После сборки необходимо установить прошивку на роутер. Подробнее в гитлабе падавана: https://gitlab.com/hadzhioglu/padavan-ng. Как устанавливать: https://4pda.to/forum/index.php?showtopic=975687&st=12980#Spoil-115912586-5

Далее скачать youtubeUnblock, закинуть его на роутер, добавить правила фаервола и запустить. Можно скачивать static бинарник и запускать вручную, а можно загрузить entware на usb или в память, и поставить соответствующую версию youtubeUblock.

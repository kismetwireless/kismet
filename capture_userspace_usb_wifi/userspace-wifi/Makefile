# Userspace USB Wi-Fi: Linux drivers built unmodified against kernel and mac80211
# emulation on libusb (see README.md)

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
FIRMWAREDIR = $(PREFIX)/share/uwifi/firmware

CC ?= cc
AR ?= ar
PKG_CONFIG ?= pkg-config

LIBUSBCFLAGS := $(shell $(PKG_CONFIG) --cflags libusb-1.0)
LIBUSBLIBS := $(shell $(PKG_CONFIG) --libs libusb-1.0)

# Compressed linux-firmware (.zst, .xz) when the libraries are present
FW_CFLAGS :=
FIRMWARELIBS :=
ifeq ($(shell $(PKG_CONFIG) --exists libzstd && echo y),y)
FW_CFLAGS += -DHAVE_LIBZSTD $(shell $(PKG_CONFIG) --cflags libzstd)
FIRMWARELIBS += $(shell $(PKG_CONFIG) --libs libzstd)
endif
ifeq ($(shell $(PKG_CONFIG) --exists liblzma && echo y),y)
FW_CFLAGS += -DHAVE_LIBLZMA $(shell $(PKG_CONFIG) --cflags liblzma)
FIRMWARELIBS += $(shell $(PKG_CONFIG) --libs liblzma)
endif

# Warnings our kernel-side code trips from kernel idioms, where the compiler knows them
WNO_CANDIDATES = unused-parameter sign-compare missing-field-initializers address-of-packed-member \
	format-truncation unknown-warning-option
WNOCFLAGS := $(foreach w,$(WNO_CANDIDATES),$(shell $(CC) -Werror -W$(w) -x c -c /dev/null -o /dev/null 2>/dev/null && echo -Wno-$(w)))

# Kernel headers resolve to kcompat first, then the unmodified upstream wireless headers
KC_INCLUDES = -Ikcompat/include -Ikcompat/upstream -Ikcompat/upstream/uapi
KC_CFLAGS = -std=gnu11 -pthread -MMD -MP $(KC_INCLUDES) $(LIBUSBCFLAGS) -O2 -g -fPIE $(CFLAGS)

# Our kernel-side code
OWN_CFLAGS = $(KC_CFLAGS) -Wall -Wextra $(WNOCFLAGS) -I. -Imac80211 -Idrivers

# Vendored kernel code, built as-is; kernel style trips warnings that aren't ours to fix
MODNAME = mt76
DRV_CFLAGS = $(KC_CFLAGS) -w -Idrivers/mt76 -DKBUILD_MODNAME='"$(MODNAME)"'
RTW88_CFLAGS = $(KC_CFLAGS) -w -Idrivers/rtw88 -DKBUILD_MODNAME='"$(MODNAME)"'

KCOMPAT_OBJS = \
	kcompat/src/core.o \
	kcompat/src/sched.o \
	kcompat/src/skb.o \
	kcompat/src/usb.o

MAC80211_OBJS = \
	mac80211/main.o \
	mac80211/rx.o \
	mac80211/tx.o \
	mac80211/cfg80211.o \
	kcompat/upstream/radiotap.o

MT76_OBJS = \
	drivers/mt76/mac80211.o \
	drivers/mt76/util.o \
	drivers/mt76/mcu.o \
	drivers/mt76/tx.o \
	drivers/mt76/eeprom.o \
	drivers/mt76/channel.o \
	drivers/mt76/agg-rx.o \
	drivers/mt76/scan.o \
	drivers/mt76/usb.o \
	drivers/mt76/mt76_connac_mcu.o \
	drivers/mt76/mt76_connac_mac.o \
	drivers/mt76/mt76_connac3_mac.o \
	drivers/mt76/mt792x_core.o \
	drivers/mt76/mt792x_mac.o \
	drivers/mt76/mt792x_usb.o \
	drivers/mt76/mt76x02_util.o \
	drivers/mt76/mt76x02_mac.o \
	drivers/mt76/mt76x02_mcu.o \
	drivers/mt76/mt76x02_eeprom.o \
	drivers/mt76/mt76x02_phy.o \
	drivers/mt76/mt76x02_txrx.o \
	drivers/mt76/mt76x02_dfs.o \
	drivers/mt76/mt76x02_beacon.o \
	drivers/mt76/mt76x02_usb_mcu.o \
	drivers/mt76/mt76x02_usb_core.o \
	drivers/mt76/mt7921/init.o \
	drivers/mt76/mt7921/main.o \
	drivers/mt76/mt7921/mac.o \
	drivers/mt76/mt7921/mcu.o \
	drivers/mt76/mt7921/usb.o \
	drivers/mt76/mt7921/regd.o \
	drivers/mt76/mt7925/init.o \
	drivers/mt76/mt7925/main.o \
	drivers/mt76/mt7925/mac.o \
	drivers/mt76/mt7925/mcu.o \
	drivers/mt76/mt7925/usb.o \
	drivers/mt76/mt7925/regd.o \
	drivers/mt76/mt7925/nan.o \
	drivers/mt76/mt76x2/eeprom.o \
	drivers/mt76/mt76x2/mac.o \
	drivers/mt76/mt76x2/init.o \
	drivers/mt76/mt76x2/phy.o \
	drivers/mt76/mt76x2/mcu.o \
	drivers/mt76/mt76x2/usb.o \
	drivers/mt76/mt76x2/usb_init.o \
	drivers/mt76/mt76x2/usb_main.o \
	drivers/mt76/mt76x2/usb_mac.o \
	drivers/mt76/mt76x2/usb_mcu.o \
	drivers/mt76/mt76x2/usb_phy.o

# rtw88 USB: core, USB transport and every chip with a USB part; no PCI, SDIO or LEDs
RTW88_OBJS = \
	drivers/rtw88/main.o \
	drivers/rtw88/mac80211.o \
	drivers/rtw88/util.o \
	drivers/rtw88/debug.o \
	drivers/rtw88/tx.o \
	drivers/rtw88/rx.o \
	drivers/rtw88/mac.o \
	drivers/rtw88/phy.o \
	drivers/rtw88/coex.o \
	drivers/rtw88/efuse.o \
	drivers/rtw88/fw.o \
	drivers/rtw88/ps.o \
	drivers/rtw88/sec.o \
	drivers/rtw88/bf.o \
	drivers/rtw88/sar.o \
	drivers/rtw88/regd.o \
	drivers/rtw88/usb.o \
	drivers/rtw88/rtw88xxa.o \
	drivers/rtw88/rtw8812a.o \
	drivers/rtw88/rtw8812a_table.o \
	drivers/rtw88/rtw8812au.o \
	drivers/rtw88/rtw8821a.o \
	drivers/rtw88/rtw8821a_table.o \
	drivers/rtw88/rtw8821au.o \
	drivers/rtw88/rtw8814a.o \
	drivers/rtw88/rtw8814a_table.o \
	drivers/rtw88/rtw8814au.o \
	drivers/rtw88/rtw8822b.o \
	drivers/rtw88/rtw8822b_table.o \
	drivers/rtw88/rtw8822bu.o \
	drivers/rtw88/rtw8822c.o \
	drivers/rtw88/rtw8822c_table.o \
	drivers/rtw88/rtw8822cu.o \
	drivers/rtw88/rtw8821c.o \
	drivers/rtw88/rtw8821c_table.o \
	drivers/rtw88/rtw8821cu.o \
	drivers/rtw88/rtw8723x.o \
	drivers/rtw88/rtw8723d.o \
	drivers/rtw88/rtw8723d_table.o \
	drivers/rtw88/rtw8723du.o

# Morse Micro MM8108 802.11ah, from Kismet's libmm8108, with mac80211 glue
MM8108_OBJS = \
	drivers/mm8108/mm8108.o \
	drivers/mm8108/mm_usb.o \
	drivers/mm8108/mm_hw.o \
	drivers/mm8108/mm_fw.o \
	drivers/mm8108/mm_yaps.o \
	drivers/mm8108/mm_cmd.o \
	drivers/mm8108/mm_channels.o \
	drivers/mm8108/mm_channel_tables.o \
	drivers/mm8108/mm_s1g.o \
	drivers/mm8108/mac.o

GLUE_OBJS = \
	drivers/mt76_glue.o

COMMON_OBJS = \
	common/uwifi.o \
	common/pcap.o \
	common/firmware_file.o

LIB = libuwifi.a
TOOL = uwifi

# The adapter as a Linux Wi-Fi device through mac80211_hwsim
ifeq ($(shell uname -s),Linux)
HWSIM_OBJS = \
	hwsim/genl.o \
	hwsim/hwsim.o
TOOL_CFLAGS = -DUWIFI_HWSIM
endif

ALL_OBJS = $(KCOMPAT_OBJS) $(MAC80211_OBJS) $(MT76_OBJS) $(RTW88_OBJS) $(MM8108_OBJS) $(GLUE_OBJS) $(COMMON_OBJS) \
	$(HWSIM_OBJS) tools/uwifi.o

# Drivers register from constructors, so the whole archive is linked
ifeq ($(shell uname -s),Darwin)
WHOLE_ARCHIVE = -Wl,-force_load,$(LIB)
else
WHOLE_ARCHIVE = -Wl,--whole-archive $(LIB) -Wl,--no-whole-archive
endif

all: $(TOOL)

$(LIB): $(KCOMPAT_OBJS) $(MAC80211_OBJS) $(MT76_OBJS) $(RTW88_OBJS) $(MM8108_OBJS) $(GLUE_OBJS) $(COMMON_OBJS) $(HWSIM_OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(TOOL): tools/uwifi.o $(LIB)
	$(CC) $(LDFLAGS) -pthread -o $@ tools/uwifi.o $(WHOLE_ARCHIVE) $(LIBUSBLIBS) $(FIRMWARELIBS) -lm

tools/uwifi.o: tools/uwifi.c
	$(CC) $(OWN_CFLAGS) $(TOOL_CFLAGS) -DFIRMWAREDIR=\"$(FIRMWAREDIR)\" -c $< -o $@

# Netlink against the system's Linux headers rather than kcompat's
hwsim/genl.o: hwsim/genl.c
	$(CC) -std=gnu11 -pthread -MMD -MP -O2 -g -fPIE -Wall -Wextra $(CFLAGS) -c $< -o $@

common/firmware_file.o: common/firmware_file.c
	$(CC) $(OWN_CFLAGS) $(FW_CFLAGS) -c $< -o $@

# Kernel module names, as the driver reports them
drivers/mt76/mt7921/usb.o: MODNAME = mt7921u
drivers/mt76/mt7925/usb.o: MODNAME = mt7925u
drivers/mt76/mt76x2/usb.o: MODNAME = mt76x2u
# Short names (rtw8814au rather than rtw88_8814au), so adapters are rtw8814a-0
drivers/rtw88/%.o: MODNAME = rtw88
drivers/rtw88/rtw8812au.o: MODNAME = rtw8812au
drivers/rtw88/rtw8821au.o: MODNAME = rtw8821au
drivers/rtw88/rtw8814au.o: MODNAME = rtw8814au
drivers/rtw88/rtw8822bu.o: MODNAME = rtw8822bu
drivers/rtw88/rtw8822cu.o: MODNAME = rtw8822cu
drivers/rtw88/rtw8821cu.o: MODNAME = rtw8821cu
drivers/rtw88/rtw8723du.o: MODNAME = rtw8723du

drivers/mt76/%.o: drivers/mt76/%.c
	$(CC) $(DRV_CFLAGS) -c $< -o $@

drivers/rtw88/%.o: drivers/rtw88/%.c
	$(CC) $(RTW88_CFLAGS) -c $< -o $@

kcompat/upstream/%.o: kcompat/upstream/%.c
	$(CC) $(KC_CFLAGS) -w -c $< -o $@

%.o: %.c
	$(CC) $(OWN_CFLAGS) -c $< -o $@

install: $(TOOL)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(FIRMWAREDIR)
	install -m 755 $(TOOL) $(DESTDIR)$(BINDIR)
	cp -R firmware/. $(DESTDIR)$(FIRMWAREDIR)

clean:
	@-rm -f $(TOOL) $(LIB) $(ALL_OBJS) $(ALL_OBJS:.o=.d)

.PHONY: all install clean

-include $(ALL_OBJS:.o=.d)

/*
 * Copyright (C) 2010 Willow Garage <http://www.willowgarage.com>
 * Copyright (C) 2004 - 2010 Ivo van Doorn <IvDoorn@gmail.com>
 * <http://rt2x00.serialmonkey.com>
 *
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 Inc
 *
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <Windows.h>
#define usleep(x) Sleep((x) < 1000 ? 1 : (x) / 1000)
#endif

#include "kernel/cfg80211.h"
#include "kernel/endian.h"
#include "kernel/kernel.h"
#include "kernel/nl80211.h"
#include "kernel/types.h"

#include "rt2x00.h"
#include "rt2x00lib.h"
#include "rt2x00usb.h"
#include "rt2800.h"
#include "rt2800usb.h"
#include "rt2800lib.h"

#define CONFIG_RT2800USB_RT55XX
#define CONFIG_RT2800USB_RT33XX
#define CONFIG_RT2800USB_RT3573
#define CONFIG_RT2800USB_RT53XX

/*
 * rt2800usb module information.
 */
static const struct usb_device_id rt2800usb_device_table[] = {
	/* Abocom */
	{ USB_DEVICE(0x07b8, 0x2870) },
	{ USB_DEVICE(0x07b8, 0x2770) },
	{ USB_DEVICE(0x07b8, 0x3070) },
	{ USB_DEVICE(0x07b8, 0x3071) },
	{ USB_DEVICE(0x07b8, 0x3072) },
	{ USB_DEVICE(0x1482, 0x3c09) },
	/* AirTies */
	{ USB_DEVICE(0x1eda, 0x2012) },
	{ USB_DEVICE(0x1eda, 0x2210) },
	{ USB_DEVICE(0x1eda, 0x2310) },
	/* Allwin */
	{ USB_DEVICE(0x8516, 0x2070) },
	{ USB_DEVICE(0x8516, 0x2770) },
	{ USB_DEVICE(0x8516, 0x2870) },
	{ USB_DEVICE(0x8516, 0x3070) },
	{ USB_DEVICE(0x8516, 0x3071) },
	{ USB_DEVICE(0x8516, 0x3072) },
	/* Alpha Networks */
	{ USB_DEVICE(0x14b2, 0x3c06) },
	{ USB_DEVICE(0x14b2, 0x3c07) },
	{ USB_DEVICE(0x14b2, 0x3c09) },
	{ USB_DEVICE(0x14b2, 0x3c12) },
	{ USB_DEVICE(0x14b2, 0x3c23) },
	{ USB_DEVICE(0x14b2, 0x3c25) },
	{ USB_DEVICE(0x14b2, 0x3c27) },
	{ USB_DEVICE(0x14b2, 0x3c28) },
	{ USB_DEVICE(0x14b2, 0x3c2c) },
	/* Amit */
	{ USB_DEVICE(0x15c5, 0x0008) },
	/* Askey */
	{ USB_DEVICE(0x1690, 0x0740) },
	/* ASUS */
	{ USB_DEVICE(0x0b05, 0x1731) },
	{ USB_DEVICE(0x0b05, 0x1732) },
	{ USB_DEVICE(0x0b05, 0x1742) },
	{ USB_DEVICE(0x0b05, 0x1784) },
	{ USB_DEVICE(0x1761, 0x0b05) },
	/* AzureWave */
	{ USB_DEVICE(0x13d3, 0x3247) },
	{ USB_DEVICE(0x13d3, 0x3273) },
	{ USB_DEVICE(0x13d3, 0x3305) },
	{ USB_DEVICE(0x13d3, 0x3307) },
	{ USB_DEVICE(0x13d3, 0x3321) },
	/* Belkin */
	{ USB_DEVICE(0x050d, 0x8053) },
	{ USB_DEVICE(0x050d, 0x805c) },
	{ USB_DEVICE(0x050d, 0x815c) },
	{ USB_DEVICE(0x050d, 0x825a) },
	{ USB_DEVICE(0x050d, 0x825b) },
	{ USB_DEVICE(0x050d, 0x935a) },
	{ USB_DEVICE(0x050d, 0x935b) },
	/* Buffalo */
	{ USB_DEVICE(0x0411, 0x00e8) },
	{ USB_DEVICE(0x0411, 0x0158) },
	{ USB_DEVICE(0x0411, 0x015d) },
	{ USB_DEVICE(0x0411, 0x016f) },
	{ USB_DEVICE(0x0411, 0x01a2) },
	{ USB_DEVICE(0x0411, 0x01ee) },
	{ USB_DEVICE(0x0411, 0x01a8) },
	{ USB_DEVICE(0x0411, 0x01fd) },
	/* Corega */
	{ USB_DEVICE(0x07aa, 0x002f) },
	{ USB_DEVICE(0x07aa, 0x003c) },
	{ USB_DEVICE(0x07aa, 0x003f) },
	{ USB_DEVICE(0x18c5, 0x0012) },
	/* D-Link */
	{ USB_DEVICE(0x07d1, 0x3c09) },
	{ USB_DEVICE(0x07d1, 0x3c0a) },
	{ USB_DEVICE(0x07d1, 0x3c0d) },
	{ USB_DEVICE(0x07d1, 0x3c0e) },
	{ USB_DEVICE(0x07d1, 0x3c0f) },
	{ USB_DEVICE(0x07d1, 0x3c11) },
	{ USB_DEVICE(0x07d1, 0x3c13) },
	{ USB_DEVICE(0x07d1, 0x3c15) },
	{ USB_DEVICE(0x07d1, 0x3c16) },
	{ USB_DEVICE(0x07d1, 0x3c17) },
	{ USB_DEVICE(0x2001, 0x3317) },
	{ USB_DEVICE(0x2001, 0x3c1b) },
	{ USB_DEVICE(0x2001, 0x3c25) },
	/* Draytek */
	{ USB_DEVICE(0x07fa, 0x7712) },
	/* DVICO */
	{ USB_DEVICE(0x0fe9, 0xb307) },
	/* Edimax */
	{ USB_DEVICE(0x7392, 0x4085) },
	{ USB_DEVICE(0x7392, 0x7711) },
	{ USB_DEVICE(0x7392, 0x7717) },
	{ USB_DEVICE(0x7392, 0x7718) },
	{ USB_DEVICE(0x7392, 0x7722) },
	/* Encore */
	{ USB_DEVICE(0x203d, 0x1480) },
	{ USB_DEVICE(0x203d, 0x14a9) },
	/* EnGenius */
	{ USB_DEVICE(0x1740, 0x9701) },
	{ USB_DEVICE(0x1740, 0x9702) },
	{ USB_DEVICE(0x1740, 0x9703) },
	{ USB_DEVICE(0x1740, 0x9705) },
	{ USB_DEVICE(0x1740, 0x9706) },
	{ USB_DEVICE(0x1740, 0x9707) },
	{ USB_DEVICE(0x1740, 0x9708) },
	{ USB_DEVICE(0x1740, 0x9709) },
	/* Gemtek */
	{ USB_DEVICE(0x15a9, 0x0012) },
	/* Gigabyte */
	{ USB_DEVICE(0x1044, 0x800b) },
	{ USB_DEVICE(0x1044, 0x800d) },
	/* Hawking */
	{ USB_DEVICE(0x0e66, 0x0001) },
	{ USB_DEVICE(0x0e66, 0x0003) },
	{ USB_DEVICE(0x0e66, 0x0009) },
	{ USB_DEVICE(0x0e66, 0x000b) },
	{ USB_DEVICE(0x0e66, 0x0013) },
	{ USB_DEVICE(0x0e66, 0x0017) },
	{ USB_DEVICE(0x0e66, 0x0018) },
	/* I-O DATA */
	{ USB_DEVICE(0x04bb, 0x0945) },
	{ USB_DEVICE(0x04bb, 0x0947) },
	{ USB_DEVICE(0x04bb, 0x0948) },
	/* Linksys */
	{ USB_DEVICE(0x13b1, 0x0031) },
	{ USB_DEVICE(0x1737, 0x0070) },
	{ USB_DEVICE(0x1737, 0x0071) },
	{ USB_DEVICE(0x1737, 0x0077) },
	{ USB_DEVICE(0x1737, 0x0078) },
	/* Logitec */
	{ USB_DEVICE(0x0789, 0x0162) },
	{ USB_DEVICE(0x0789, 0x0163) },
	{ USB_DEVICE(0x0789, 0x0164) },
	{ USB_DEVICE(0x0789, 0x0166) },
	/* Motorola */
	{ USB_DEVICE(0x100d, 0x9031) },
	/* MSI */
	{ USB_DEVICE(0x0db0, 0x3820) },
	{ USB_DEVICE(0x0db0, 0x3821) },
	{ USB_DEVICE(0x0db0, 0x3822) },
	{ USB_DEVICE(0x0db0, 0x3870) },
	{ USB_DEVICE(0x0db0, 0x3871) },
	{ USB_DEVICE(0x0db0, 0x6899) },
	{ USB_DEVICE(0x0db0, 0x821a) },
	{ USB_DEVICE(0x0db0, 0x822a) },
	{ USB_DEVICE(0x0db0, 0x822b) },
	{ USB_DEVICE(0x0db0, 0x822c) },
	{ USB_DEVICE(0x0db0, 0x870a) },
	{ USB_DEVICE(0x0db0, 0x871a) },
	{ USB_DEVICE(0x0db0, 0x871b) },
	{ USB_DEVICE(0x0db0, 0x871c) },
	{ USB_DEVICE(0x0db0, 0x899a) },
	/* Ovislink */
	{ USB_DEVICE(0x1b75, 0x3070) },
	{ USB_DEVICE(0x1b75, 0x3071) },
	{ USB_DEVICE(0x1b75, 0x3072) },
	{ USB_DEVICE(0x1b75, 0xa200) },
	/* Para */
	{ USB_DEVICE(0x20b8, 0x8888) },
	/* Pegatron */
	{ USB_DEVICE(0x1d4d, 0x0002) },
	{ USB_DEVICE(0x1d4d, 0x000c) },
	{ USB_DEVICE(0x1d4d, 0x000e) },
	{ USB_DEVICE(0x1d4d, 0x0011) },
	/* Philips */
	{ USB_DEVICE(0x0471, 0x200f) },
	/* Planex */
	{ USB_DEVICE(0x2019, 0x5201) },
	{ USB_DEVICE(0x2019, 0xab25) },
	{ USB_DEVICE(0x2019, 0xed06) },
	/* Quanta */
	{ USB_DEVICE(0x1a32, 0x0304) },
	/* Ralink */
	{ USB_DEVICE(0x148f, 0x2070) },
	{ USB_DEVICE(0x148f, 0x2770) },
	{ USB_DEVICE(0x148f, 0x2870) },
	{ USB_DEVICE(0x148f, 0x3070) },
	{ USB_DEVICE(0x148f, 0x3071) },
	{ USB_DEVICE(0x148f, 0x3072) },
	/* Samsung */
	{ USB_DEVICE(0x04e8, 0x2018) },
	/* Siemens */
	{ USB_DEVICE(0x129b, 0x1828) },
	/* Sitecom */
	{ USB_DEVICE(0x0df6, 0x0017) },
	{ USB_DEVICE(0x0df6, 0x002b) },
	{ USB_DEVICE(0x0df6, 0x002c) },
	{ USB_DEVICE(0x0df6, 0x002d) },
	{ USB_DEVICE(0x0df6, 0x0039) },
	{ USB_DEVICE(0x0df6, 0x003b) },
	{ USB_DEVICE(0x0df6, 0x003d) },
	{ USB_DEVICE(0x0df6, 0x003e) },
	{ USB_DEVICE(0x0df6, 0x003f) },
	{ USB_DEVICE(0x0df6, 0x0040) },
	{ USB_DEVICE(0x0df6, 0x0042) },
	{ USB_DEVICE(0x0df6, 0x0047) },
	{ USB_DEVICE(0x0df6, 0x0048) },
	{ USB_DEVICE(0x0df6, 0x0051) },
	{ USB_DEVICE(0x0df6, 0x005f) },
	{ USB_DEVICE(0x0df6, 0x0060) },
	/* SMC */
	{ USB_DEVICE(0x083a, 0x6618) },
	{ USB_DEVICE(0x083a, 0x7511) },
	{ USB_DEVICE(0x083a, 0x7512) },
	{ USB_DEVICE(0x083a, 0x7522) },
	{ USB_DEVICE(0x083a, 0x8522) },
	{ USB_DEVICE(0x083a, 0xa618) },
	{ USB_DEVICE(0x083a, 0xa701) },
	{ USB_DEVICE(0x083a, 0xa702) },
	{ USB_DEVICE(0x083a, 0xa703) },
	{ USB_DEVICE(0x083a, 0xb522) },
	/* Sparklan */
	{ USB_DEVICE(0x15a9, 0x0006) },
	/* Sweex */
	{ USB_DEVICE(0x177f, 0x0153) },
	{ USB_DEVICE(0x177f, 0x0164) },
	{ USB_DEVICE(0x177f, 0x0302) },
	{ USB_DEVICE(0x177f, 0x0313) },
	{ USB_DEVICE(0x177f, 0x0323) },
	{ USB_DEVICE(0x177f, 0x0324) },
	/* U-Media */
	{ USB_DEVICE(0x157e, 0x300e) },
	{ USB_DEVICE(0x157e, 0x3013) },
	/* ZCOM */
	{ USB_DEVICE(0x0cde, 0x0022) },
	{ USB_DEVICE(0x0cde, 0x0025) },
	/* Zinwell */
	{ USB_DEVICE(0x5a57, 0x0280) },
	{ USB_DEVICE(0x5a57, 0x0282) },
	{ USB_DEVICE(0x5a57, 0x0283) },
	{ USB_DEVICE(0x5a57, 0x5257) },
	/* Zyxel */
	{ USB_DEVICE(0x0586, 0x3416) },
	{ USB_DEVICE(0x0586, 0x3418) },
	{ USB_DEVICE(0x0586, 0x341a) },
	{ USB_DEVICE(0x0586, 0x341e) },
	{ USB_DEVICE(0x0586, 0x343e) },
#ifdef CONFIG_RT2800USB_RT33XX
	/* Belkin */
	{ USB_DEVICE(0x050d, 0x945b) },
	/* D-Link */
	{ USB_DEVICE(0x2001, 0x3c17) },
	/* Panasonic */
	{ USB_DEVICE(0x083a, 0xb511) },
	/* Accton/Arcadyan/Epson */
	{ USB_DEVICE(0x083a, 0xb512) },
	/* Philips */
	{ USB_DEVICE(0x0471, 0x20dd) },
	/* Ralink */
	{ USB_DEVICE(0x148f, 0x3370) },
	{ USB_DEVICE(0x148f, 0x8070) },
	/* Sitecom */
	{ USB_DEVICE(0x0df6, 0x0050) },
	/* Sweex */
	{ USB_DEVICE(0x177f, 0x0163) },
	{ USB_DEVICE(0x177f, 0x0165) },
#endif
#ifdef CONFIG_RT2800USB_RT35XX
	/* Allwin */
	{ USB_DEVICE(0x8516, 0x3572) },
	/* Askey */
	{ USB_DEVICE(0x1690, 0x0744) },
	{ USB_DEVICE(0x1690, 0x0761) },
	{ USB_DEVICE(0x1690, 0x0764) },
	/* ASUS */
	{ USB_DEVICE(0x0b05, 0x179d) },
	/* Cisco */
	{ USB_DEVICE(0x167b, 0x4001) },
	/* EnGenius */
	{ USB_DEVICE(0x1740, 0x9801) },
	/* I-O DATA */
	{ USB_DEVICE(0x04bb, 0x0944) },
	/* Linksys */
	{ USB_DEVICE(0x13b1, 0x002f) },
	{ USB_DEVICE(0x1737, 0x0079) },
	/* Logitec */
	{ USB_DEVICE(0x0789, 0x0170) },
	/* Ralink */
	{ USB_DEVICE(0x148f, 0x3572) },
	/* Sitecom */
	{ USB_DEVICE(0x0df6, 0x0041) },
	{ USB_DEVICE(0x0df6, 0x0062) },
	{ USB_DEVICE(0x0df6, 0x0065) },
	{ USB_DEVICE(0x0df6, 0x0066) },
	{ USB_DEVICE(0x0df6, 0x0068) },
	/* Toshiba */
	{ USB_DEVICE(0x0930, 0x0a07) },
	/* Zinwell */
	{ USB_DEVICE(0x5a57, 0x0284) },
#endif
#ifdef CONFIG_RT2800USB_RT3573
	/* AirLive */
	{ USB_DEVICE(0x1b75, 0x7733) },
	/* ASUS */
	{ USB_DEVICE(0x0b05, 0x17bc) },
	{ USB_DEVICE(0x0b05, 0x17ad) },
	/* Belkin */
	{ USB_DEVICE(0x050d, 0x1103) },
	/* Cameo */
	{ USB_DEVICE(0x148f, 0xf301) },
	/* D-Link */
	{ USB_DEVICE(0x2001, 0x3c1f) },
	/* Edimax */
	{ USB_DEVICE(0x7392, 0x7733) },
	/* Hawking */
	{ USB_DEVICE(0x0e66, 0x0020) },
	{ USB_DEVICE(0x0e66, 0x0021) },
	/* I-O DATA */
	{ USB_DEVICE(0x04bb, 0x094e) },
	/* Linksys */
	{ USB_DEVICE(0x13b1, 0x003b) },
	/* Logitec */
	{ USB_DEVICE(0x0789, 0x016b) },
	/* NETGEAR */
	{ USB_DEVICE(0x0846, 0x9012) },
	{ USB_DEVICE(0x0846, 0x9013) },
	{ USB_DEVICE(0x0846, 0x9019) },
	/* Planex */
	{ USB_DEVICE(0x2019, 0xed19) },
	/* Ralink */
	{ USB_DEVICE(0x148f, 0x3573) },
	/* Sitecom */
	{ USB_DEVICE(0x0df6, 0x0067) },
	{ USB_DEVICE(0x0df6, 0x006a) },
	{ USB_DEVICE(0x0df6, 0x006e) },
	/* ZyXEL */
	{ USB_DEVICE(0x0586, 0x3421) },
#endif
#ifdef CONFIG_RT2800USB_RT53XX
	/* Arcadyan */
	{ USB_DEVICE(0x043e, 0x7a12) },
	{ USB_DEVICE(0x043e, 0x7a32) },
	/* ASUS */
	{ USB_DEVICE(0x0b05, 0x17e8) },
	/* Azurewave */
	{ USB_DEVICE(0x13d3, 0x3329) },
	{ USB_DEVICE(0x13d3, 0x3365) },
	/* D-Link */
	{ USB_DEVICE(0x2001, 0x3c15) },
	{ USB_DEVICE(0x2001, 0x3c19) },
	{ USB_DEVICE(0x2001, 0x3c1c) },
	{ USB_DEVICE(0x2001, 0x3c1d) },
	{ USB_DEVICE(0x2001, 0x3c1e) },
	{ USB_DEVICE(0x2001, 0x3c20) },
	{ USB_DEVICE(0x2001, 0x3c22) },
	{ USB_DEVICE(0x2001, 0x3c23) },
	/* LG innotek */
	{ USB_DEVICE(0x043e, 0x7a22) },
	{ USB_DEVICE(0x043e, 0x7a42) },
	/* Panasonic */
	{ USB_DEVICE(0x04da, 0x1801) },
	{ USB_DEVICE(0x04da, 0x1800) },
	{ USB_DEVICE(0x04da, 0x23f6) },
	/* Philips */
	{ USB_DEVICE(0x0471, 0x2104) },
	{ USB_DEVICE(0x0471, 0x2126) },
	{ USB_DEVICE(0x0471, 0x2180) },
	{ USB_DEVICE(0x0471, 0x2181) },
	{ USB_DEVICE(0x0471, 0x2182) },
	/* Ralink */
	{ USB_DEVICE(0x148f, 0x5370) },
	{ USB_DEVICE(0x148f, 0x5372) },
#endif
#ifdef CONFIG_RT2800USB_RT55XX
	/* Arcadyan */
	{ USB_DEVICE(0x043e, 0x7a32) },
	/* AVM GmbH */
	{ USB_DEVICE(0x057c, 0x8501) },
	/* Buffalo */
	{ USB_DEVICE(0x0411, 0x0241) },
	{ USB_DEVICE(0x0411, 0x0253) },
	/* D-Link */
	{ USB_DEVICE(0x2001, 0x3c1a) },
	{ USB_DEVICE(0x2001, 0x3c21) },
	/* Proware */
	{ USB_DEVICE(0x043e, 0x7a13) },
	/* Ralink */
	{ USB_DEVICE(0x148f, 0x5572) },
	/* TRENDnet */
	{ USB_DEVICE(0x20f4, 0x724a) },
#endif
#ifdef CONFIG_RT2800USB_UNKNOWN
	/*
	 * Unclear what kind of devices these are (they aren't supported by the
	 * vendor linux driver).
	 */
	/* Abocom */
	{ USB_DEVICE(0x07b8, 0x3073) },
	{ USB_DEVICE(0x07b8, 0x3074) },
	/* Alpha Networks */
	{ USB_DEVICE(0x14b2, 0x3c08) },
	{ USB_DEVICE(0x14b2, 0x3c11) },
	/* Amigo */
	{ USB_DEVICE(0x0e0b, 0x9031) },
	{ USB_DEVICE(0x0e0b, 0x9041) },
	/* ASUS */
	{ USB_DEVICE(0x0b05, 0x166a) },
	{ USB_DEVICE(0x0b05, 0x1760) },
	{ USB_DEVICE(0x0b05, 0x1761) },
	{ USB_DEVICE(0x0b05, 0x1790) },
	{ USB_DEVICE(0x0b05, 0x17a7) },
	/* AzureWave */
	{ USB_DEVICE(0x13d3, 0x3262) },
	{ USB_DEVICE(0x13d3, 0x3284) },
	{ USB_DEVICE(0x13d3, 0x3322) },
	{ USB_DEVICE(0x13d3, 0x3340) },
	{ USB_DEVICE(0x13d3, 0x3399) },
	{ USB_DEVICE(0x13d3, 0x3400) },
	{ USB_DEVICE(0x13d3, 0x3401) },
	/* Belkin */
	{ USB_DEVICE(0x050d, 0x1003) },
	/* Buffalo */
	{ USB_DEVICE(0x0411, 0x012e) },
	{ USB_DEVICE(0x0411, 0x0148) },
	{ USB_DEVICE(0x0411, 0x0150) },
	/* Corega */
	{ USB_DEVICE(0x07aa, 0x0041) },
	{ USB_DEVICE(0x07aa, 0x0042) },
	{ USB_DEVICE(0x18c5, 0x0008) },
	/* D-Link */
	{ USB_DEVICE(0x07d1, 0x3c0b) },
	/* Encore */
	{ USB_DEVICE(0x203d, 0x14a1) },
	/* EnGenius */
	{ USB_DEVICE(0x1740, 0x0600) },
	{ USB_DEVICE(0x1740, 0x0602) },
	/* Gemtek */
	{ USB_DEVICE(0x15a9, 0x0010) },
	/* Gigabyte */
	{ USB_DEVICE(0x1044, 0x800c) },
	/* Hercules */
	{ USB_DEVICE(0x06f8, 0xe036) },
	/* Huawei */
	{ USB_DEVICE(0x148f, 0xf101) },
	/* I-O DATA */
	{ USB_DEVICE(0x04bb, 0x094b) },
	/* LevelOne */
	{ USB_DEVICE(0x1740, 0x0605) },
	{ USB_DEVICE(0x1740, 0x0615) },
	/* Logitec */
	{ USB_DEVICE(0x0789, 0x0168) },
	{ USB_DEVICE(0x0789, 0x0169) },
	/* Motorola */
	{ USB_DEVICE(0x100d, 0x9032) },
	/* Pegatron */
	{ USB_DEVICE(0x05a6, 0x0101) },
	{ USB_DEVICE(0x1d4d, 0x0010) },
	/* Planex */
	{ USB_DEVICE(0x2019, 0xab24) },
	{ USB_DEVICE(0x2019, 0xab29) },
	/* Qcom */
	{ USB_DEVICE(0x18e8, 0x6259) },
	/* RadioShack */
	{ USB_DEVICE(0x08b9, 0x1197) },
	/* Sitecom */
	{ USB_DEVICE(0x0df6, 0x003c) },
	{ USB_DEVICE(0x0df6, 0x004a) },
	{ USB_DEVICE(0x0df6, 0x004d) },
	{ USB_DEVICE(0x0df6, 0x0053) },
	{ USB_DEVICE(0x0df6, 0x0069) },
	{ USB_DEVICE(0x0df6, 0x006f) },
	{ USB_DEVICE(0x0df6, 0x0078) },
	/* SMC */
	{ USB_DEVICE(0x083a, 0xa512) },
	{ USB_DEVICE(0x083a, 0xc522) },
	{ USB_DEVICE(0x083a, 0xd522) },
	{ USB_DEVICE(0x083a, 0xf511) },
	/* Sweex */
	{ USB_DEVICE(0x177f, 0x0254) },
	/* TP-LINK */
	{ USB_DEVICE(0xf201, 0x5370) },
#endif
};

/*
 * Firmware functions
 */
int rt2800usb_autorun_detect(struct rt2x00_dev *rt2x00dev) {
    ___le32 *reg;
    uint32_t fw_mode;
    int ret;

    reg = (___le32 *) malloc(sizeof(___le32));
    if (reg == NULL)
        return -ENOMEM;

    /* cannot use rt2x00usb_register_read here as it uses different
     * mode (MULTI_READ vs. DEVICE_MODE) and does not pass the
     * magic value USB_MODE_AUTORUN (0x11) to the device, thus the
     * returned value would be invalid.
     */
    ret = rt2x00usb_vendor_request(rt2x00dev, USB_DEVICE_MODE,
            USB_VENDOR_REQUEST_IN, 0,
            USB_MODE_AUTORUN, reg, sizeof(___le32),
            REGISTER_TIMEOUT_FIRMWARE);
    fw_mode = le32_to_cpu(*reg);

    free(reg);

    if (ret < 0)
        return ret;

    if ((fw_mode & 0x00000003) == 2)
        return 1;

    return 0;
}

static char *rt2800usb_get_firmware_name(struct rt2x00_dev *rt2x00dev) {
	return FIRMWARE_RT2870;
}

static int rt2800usb_write_firmware(struct rt2x00_dev *rt2x00dev,
        const uint8_t *data, const size_t len) {
    int status;
    uint32_t offset;
    uint32_t length;
    int retval;

    /*
     * Check which section of the firmware we need.
     */
    if (rt2x00_rt(rt2x00dev, RT2860) ||
            rt2x00_rt(rt2x00dev, RT2872) ||
            rt2x00_rt(rt2x00dev, RT3070)) {
        offset = 0;
        length = 4096;
    } else {
        offset = 4096;
        length = 4096;
    }

    /*
     * Write firmware to device.
     */
    retval = rt2800usb_autorun_detect(rt2x00dev);
    if (retval < 0)
        return retval;
    if (retval) {
        rt2x00_info(rt2x00dev,
                "Firmware loading not required - NIC in AutoRun mode\n");
        __clear_bit(REQUIRE_FIRMWARE, &rt2x00dev->cap_flags);
    } else {
        rt2x00_info(rt2x00dev, "Starting register_multiwrite for FIRMWARE_IMAGE_BASE at offset %d len %d sz %lu\n", offset, length, len);
        rt2x00usb_register_multiwrite(rt2x00dev, FIRMWARE_IMAGE_BASE,
                data + offset, length);
    }

    rt2x00usb_register_write(rt2x00dev, H2M_MAILBOX_CID, ~0);
    rt2x00usb_register_write(rt2x00dev, H2M_MAILBOX_STATUS, ~0);

    /*
     * Send firmware request to device to load firmware,
     * we need to specify a long timeout time.
     */
    status = rt2x00usb_vendor_request_sw(rt2x00dev, USB_DEVICE_MODE,
            0, USB_MODE_FIRMWARE,
            REGISTER_TIMEOUT_FIRMWARE);
    if (status < 0) {
        rt2x00_err(rt2x00dev, "Failed to write Firmware to device\n");
        return status;
    }

    usleep(10);
    rt2x00usb_register_write(rt2x00dev, H2M_MAILBOX_CSR, 0);

    return 0;
}

/*
 * Userspace modified start queue to only deal with triggering
 * the rx registers and dropping the queue changes and linkages,
 * modifying the device signature
 */
static void rt2800usb_start_queue(struct rt2x00_dev *rt2x00dev)
{
	uint32_t reg;

    rt2x00_info(rt2x00dev, "Starting RX queue\n");

    reg = rt2x00usb_register_read(rt2x00dev, MAC_SYS_CTRL);
    rt2x00_set_field32(&reg, MAC_SYS_CTRL_ENABLE_RX, 1);
    rt2x00usb_register_write(rt2x00dev, MAC_SYS_CTRL, reg);
}

/* 
 * Userspace modified stop queue to only deal with rx and 
 * registers, removing the rest and changing the function signature 
 */
static void rt2800usb_stop_queue(struct rt2x00_dev *rt2x00dev)
{
	uint32_t reg;

    rt2x00_info(rt2x00dev, "Stopping RX queue\n");

    reg = rt2x00usb_register_read(rt2x00dev, MAC_SYS_CTRL);
    rt2x00_set_field32(&reg, MAC_SYS_CTRL_ENABLE_RX, 0);
    rt2x00usb_register_write(rt2x00dev, MAC_SYS_CTRL, reg);
}

/*
 * Device state switch handlers.
 */
static int rt2800usb_init_registers(struct rt2x00_dev *rt2x00dev) {
    uint32_t reg;

    rt2x00_info(rt2x00dev, "rt2800usb_init_registers\n");

    /*
     * Wait until BBP and RF are ready.
     */
    if (rt2800_wait_csr_ready(rt2x00dev))
        return -EBUSY;

    reg = rt2x00usb_register_read(rt2x00dev, PBF_SYS_CTRL);
    rt2x00usb_register_write(rt2x00dev, PBF_SYS_CTRL, reg & ~0x00002000);

    reg = 0;
    rt2x00_set_field32(&reg, MAC_SYS_CTRL_RESET_CSR, 1);
    rt2x00_set_field32(&reg, MAC_SYS_CTRL_RESET_BBP, 1);
    rt2x00usb_register_write(rt2x00dev, MAC_SYS_CTRL, reg);

    rt2x00usb_vendor_request_sw(rt2x00dev, USB_DEVICE_MODE, 0,
            USB_MODE_RESET, REGISTER_TIMEOUT);

    rt2x00usb_register_write(rt2x00dev, MAC_SYS_CTRL, 0x00000000);

    return 0;
}

static int rt2800usb_enable_radio(struct rt2x00_dev *rt2x00dev) {
    uint32_t reg = 0;

    if (unlikely(rt2800_wait_wpdma_ready(rt2x00dev)))
        return -EIO;

    rt2x00_set_field32(&reg, USB_DMA_CFG_PHY_CLEAR, 0);
    rt2x00_set_field32(&reg, USB_DMA_CFG_RX_BULK_AGG_EN, 0);
    rt2x00_set_field32(&reg, USB_DMA_CFG_RX_BULK_AGG_TIMEOUT, 128);
    /*
     * Total room for RX frames in kilobytes, PBF might still exceed
     * this limit so reduce the number to prevent errors.
     */

    /* 
     * We don't implement real skb and queues and such in userspace
     * so hardcode the rt2x00dev->rx->limit queue to 128 
     */
    rt2x00_set_field32(&reg, USB_DMA_CFG_RX_BULK_AGG_LIMIT,
            ((128 * DATA_FRAME_SIZE)
             / 1024) - 3);
    rt2x00_set_field32(&reg, USB_DMA_CFG_RX_BULK_EN, 1);
    rt2x00_set_field32(&reg, USB_DMA_CFG_TX_BULK_EN, 1);
    rt2x00usb_register_write(rt2x00dev, USB_DMA_CFG, reg);

    return rt2800_enable_radio(rt2x00dev);
}

static void rt2800usb_disable_radio(struct rt2x00_dev *rt2x00dev) {
    rt2800_disable_radio(rt2x00dev);
}

static int rt2800usb_set_state(struct rt2x00_dev *rt2x00dev,
        enum dev_state state) {
    if (state == STATE_AWAKE)
        rt2800_mcu_request(rt2x00dev, MCU_WAKEUP, 0xff, 0, 2);
    else
        rt2800_mcu_request(rt2x00dev, MCU_SLEEP, 0xff, 0xff, 2);

    return 0;
}

static int rt2800usb_set_device_state(struct rt2x00_dev *rt2x00dev,
        enum dev_state state) {
    int retval = 0;

    switch (state) {
        case STATE_RADIO_ON:
            rt2x00_info(rt2x00dev, "Setting radio on\n");
            /*
             * Before the radio can be enabled, the device first has
             * to be woken up. After that it needs a bit of time
             * to be fully awake and then the radio can be enabled.
             */
            rt2800usb_set_state(rt2x00dev, STATE_AWAKE);
            msleep(1);
            retval = rt2800usb_enable_radio(rt2x00dev);
            break;
        case STATE_RADIO_OFF:
            rt2x00_info(rt2x00dev, "Setting radio off\n");
            /*
             * After the radio has been disabled, the device should
             * be put to sleep for powersaving.
             */
            rt2800usb_disable_radio(rt2x00dev);
            rt2800usb_set_state(rt2x00dev, STATE_SLEEP);
            break;
        case STATE_RADIO_IRQ_ON:
        case STATE_RADIO_IRQ_OFF:
            /* No support, but no error either */
            break;
        case STATE_DEEP_SLEEP:
        case STATE_SLEEP:
        case STATE_STANDBY:
        case STATE_AWAKE:
            rt2x00_info(rt2x00dev, "Setting state awake/standby/sleep\n");
            retval = rt2800usb_set_state(rt2x00dev, state);
            break;
        default:
            retval = -ENOTSUPP;
            break;
    }

    if (unlikely(retval))
        rt2x00_err(rt2x00dev, "Device failed to enter state %d (%d)\n",
                state, retval);

    return retval;
}

/*
 * Device probe functions.
 */
static int rt2800usb_efuse_detect(struct rt2x00_dev *rt2x00dev) {
    int retval;

    retval = rt2800usb_autorun_detect(rt2x00dev);
    if (retval < 0)
        return retval;
    if (retval)
        return 1;
    return rt2800_efuse_detect(rt2x00dev);
}

static int rt2800usb_read_eeprom(struct rt2x00_dev *rt2x00dev) {
    int retval;

    retval = rt2800usb_efuse_detect(rt2x00dev);
    if (retval < 0)
        return retval;
    if (retval)
        retval = rt2800_read_eeprom_efuse(rt2x00dev);
    else
        retval = rt2x00usb_eeprom_read(rt2x00dev, rt2x00dev->eeprom,
                EEPROM_SIZE);

    return retval;
}

static const unsigned int rt2800_eeprom_map[EEPROM_WORD_COUNT] = {
	[EEPROM_CHIP_ID]		= 0x0000,
	[EEPROM_VERSION]		= 0x0001,
	[EEPROM_MAC_ADDR_0]		= 0x0002,
	[EEPROM_MAC_ADDR_1]		= 0x0003,
	[EEPROM_MAC_ADDR_2]		= 0x0004,
	[EEPROM_NIC_CONF0]		= 0x001a,
	[EEPROM_NIC_CONF1]		= 0x001b,
	[EEPROM_FREQ]			= 0x001d,
	[EEPROM_LED_AG_CONF]		= 0x001e,
	[EEPROM_LED_ACT_CONF]		= 0x001f,
	[EEPROM_LED_POLARITY]		= 0x0020,
	[EEPROM_NIC_CONF2]		= 0x0021,
	[EEPROM_LNA]			= 0x0022,
	[EEPROM_RSSI_BG]		= 0x0023,
	[EEPROM_RSSI_BG2]		= 0x0024,
	[EEPROM_TXMIXER_GAIN_BG]	= 0x0024, /* overlaps with RSSI_BG2 */
	[EEPROM_RSSI_A]			= 0x0025,
	[EEPROM_RSSI_A2]		= 0x0026,
	[EEPROM_TXMIXER_GAIN_A]		= 0x0026, /* overlaps with RSSI_A2 */
	[EEPROM_EIRP_MAX_TX_POWER]	= 0x0027,
	[EEPROM_TXPOWER_DELTA]		= 0x0028,
	[EEPROM_TXPOWER_BG1]		= 0x0029,
	[EEPROM_TXPOWER_BG2]		= 0x0030,
	[EEPROM_TSSI_BOUND_BG1]		= 0x0037,
	[EEPROM_TSSI_BOUND_BG2]		= 0x0038,
	[EEPROM_TSSI_BOUND_BG3]		= 0x0039,
	[EEPROM_TSSI_BOUND_BG4]		= 0x003a,
	[EEPROM_TSSI_BOUND_BG5]		= 0x003b,
	[EEPROM_TXPOWER_A1]		= 0x003c,
	[EEPROM_TXPOWER_A2]		= 0x0053,
	[EEPROM_TXPOWER_INIT]		= 0x0068,
	[EEPROM_TSSI_BOUND_A1]		= 0x006a,
	[EEPROM_TSSI_BOUND_A2]		= 0x006b,
	[EEPROM_TSSI_BOUND_A3]		= 0x006c,
	[EEPROM_TSSI_BOUND_A4]		= 0x006d,
	[EEPROM_TSSI_BOUND_A5]		= 0x006e,
	[EEPROM_TXPOWER_BYRATE]		= 0x006f,
	[EEPROM_BBP_START]		= 0x0078,
};

static const unsigned int rt2800_eeprom_map_ext[EEPROM_WORD_COUNT] = {
	[EEPROM_CHIP_ID]		= 0x0000,
	[EEPROM_VERSION]		= 0x0001,
	[EEPROM_MAC_ADDR_0]		= 0x0002,
	[EEPROM_MAC_ADDR_1]		= 0x0003,
	[EEPROM_MAC_ADDR_2]		= 0x0004,
	[EEPROM_NIC_CONF0]		= 0x001a,
	[EEPROM_NIC_CONF1]		= 0x001b,
	[EEPROM_NIC_CONF2]		= 0x001c,
	[EEPROM_EIRP_MAX_TX_POWER]	= 0x0020,
	[EEPROM_FREQ]			= 0x0022,
	[EEPROM_LED_AG_CONF]		= 0x0023,
	[EEPROM_LED_ACT_CONF]		= 0x0024,
	[EEPROM_LED_POLARITY]		= 0x0025,
	[EEPROM_LNA]			= 0x0026,
	[EEPROM_EXT_LNA2]		= 0x0027,
	[EEPROM_RSSI_BG]		= 0x0028,
	[EEPROM_RSSI_BG2]		= 0x0029,
	[EEPROM_RSSI_A]			= 0x002a,
	[EEPROM_RSSI_A2]		= 0x002b,
	[EEPROM_TXPOWER_BG1]		= 0x0030,
	[EEPROM_TXPOWER_BG2]		= 0x0037,
	[EEPROM_EXT_TXPOWER_BG3]	= 0x003e,
	[EEPROM_TSSI_BOUND_BG1]		= 0x0045,
	[EEPROM_TSSI_BOUND_BG2]		= 0x0046,
	[EEPROM_TSSI_BOUND_BG3]		= 0x0047,
	[EEPROM_TSSI_BOUND_BG4]		= 0x0048,
	[EEPROM_TSSI_BOUND_BG5]		= 0x0049,
	[EEPROM_TXPOWER_A1]		= 0x004b,
	[EEPROM_TXPOWER_A2]		= 0x0065,
	[EEPROM_EXT_TXPOWER_A3]		= 0x007f,
	[EEPROM_TSSI_BOUND_A1]		= 0x009a,
	[EEPROM_TSSI_BOUND_A2]		= 0x009b,
	[EEPROM_TSSI_BOUND_A3]		= 0x009c,
	[EEPROM_TSSI_BOUND_A4]		= 0x009d,
	[EEPROM_TSSI_BOUND_A5]		= 0x009e,
	[EEPROM_TXPOWER_BYRATE]		= 0x00a0,
};

static unsigned int rt2800_eeprom_word_index(struct rt2x00_dev *rt2x00dev,
					     const enum rt2800_eeprom_word word)
{
	const unsigned int *map;
	unsigned int index;

	if (word >= EEPROM_WORD_COUNT) {
        rt2x00_info(rt2x00dev, "invalid EEPROM word %d\n", word);
		return 0;
    }

	if (rt2x00_rt(rt2x00dev, RT3593) ||
	    rt2x00_rt(rt2x00dev, RT3883))
		map = rt2800_eeprom_map_ext;
	else
		map = rt2800_eeprom_map;

	index = map[word];

	/* Index 0 is valid only for EEPROM_CHIP_ID.
	 * Otherwise it means that the offset of the
	 * given word is not initialized in the map,
	 * or that the field is not usable on the
	 * actual chipset.
	 */
	WARN_ONCE(word != EEPROM_CHIP_ID && index == 0,
		  "invalid access of EEPROM word %d\n", word);

	return index;
}

#if 0
static void *rt2800_eeprom_addr(struct rt2x00_dev *rt2x00dev,
				const enum rt2800_eeprom_word word)
{
	unsigned int index;

	index = rt2800_eeprom_word_index(rt2x00dev, word);
	return rt2x00_eeprom_addr(rt2x00dev, index);
}
#endif

static uint16_t rt2800_eeprom_read(struct rt2x00_dev *rt2x00dev,
			      const enum rt2800_eeprom_word word)
{
	unsigned int index;

	index = rt2800_eeprom_word_index(rt2x00dev, word);
	return rt2x00_eeprom_read(rt2x00dev, index);
}

#if 0
static void rt2800_eeprom_write(struct rt2x00_dev *rt2x00dev,
				const enum rt2800_eeprom_word word, uint16_t data)
{
	unsigned int index;

	index = rt2800_eeprom_word_index(rt2x00dev, word);
	rt2x00_eeprom_write(rt2x00dev, index, data);
}

static uint16_t rt2800_eeprom_read_from_array(struct rt2x00_dev *rt2x00dev,
					 const enum rt2800_eeprom_word array,
					 unsigned int offset)
{
	unsigned int index;

	index = rt2800_eeprom_word_index(rt2x00dev, array);
	return rt2x00_eeprom_read(rt2x00dev, index + offset);
}
#endif

/*
 * Driver initialization handlers.
 */
const struct rt2x00_rate rt2x00_supported_rates[12] = {
	{
		.flags = DEV_RATE_CCK,
		.bitrate = 10,
		.ratemask = BIT(0),
		.plcp = 0x00,
		.mcs = RATE_MCS(RATE_MODE_CCK, 0),
	},
	{
		.flags = DEV_RATE_CCK | DEV_RATE_SHORT_PREAMBLE,
		.bitrate = 20,
		.ratemask = BIT(1),
		.plcp = 0x01,
		.mcs = RATE_MCS(RATE_MODE_CCK, 1),
	},
	{
		.flags = DEV_RATE_CCK | DEV_RATE_SHORT_PREAMBLE,
		.bitrate = 55,
		.ratemask = BIT(2),
		.plcp = 0x02,
		.mcs = RATE_MCS(RATE_MODE_CCK, 2),
	},
	{
		.flags = DEV_RATE_CCK | DEV_RATE_SHORT_PREAMBLE,
		.bitrate = 110,
		.ratemask = BIT(3),
		.plcp = 0x03,
		.mcs = RATE_MCS(RATE_MODE_CCK, 3),
	},
	{
		.flags = DEV_RATE_OFDM,
		.bitrate = 60,
		.ratemask = BIT(4),
		.plcp = 0x0b,
		.mcs = RATE_MCS(RATE_MODE_OFDM, 0),
	},
	{
		.flags = DEV_RATE_OFDM,
		.bitrate = 90,
		.ratemask = BIT(5),
		.plcp = 0x0f,
		.mcs = RATE_MCS(RATE_MODE_OFDM, 1),
	},
	{
		.flags = DEV_RATE_OFDM,
		.bitrate = 120,
		.ratemask = BIT(6),
		.plcp = 0x0a,
		.mcs = RATE_MCS(RATE_MODE_OFDM, 2),
	},
	{
		.flags = DEV_RATE_OFDM,
		.bitrate = 180,
		.ratemask = BIT(7),
		.plcp = 0x0e,
		.mcs = RATE_MCS(RATE_MODE_OFDM, 3),
	},
	{
		.flags = DEV_RATE_OFDM,
		.bitrate = 240,
		.ratemask = BIT(8),
		.plcp = 0x09,
		.mcs = RATE_MCS(RATE_MODE_OFDM, 4),
	},
	{
		.flags = DEV_RATE_OFDM,
		.bitrate = 360,
		.ratemask = BIT(9),
		.plcp = 0x0d,
		.mcs = RATE_MCS(RATE_MODE_OFDM, 5),
	},
	{
		.flags = DEV_RATE_OFDM,
		.bitrate = 480,
		.ratemask = BIT(10),
		.plcp = 0x08,
		.mcs = RATE_MCS(RATE_MODE_OFDM, 6),
	},
	{
		.flags = DEV_RATE_OFDM,
		.bitrate = 540,
		.ratemask = BIT(11),
		.plcp = 0x0c,
		.mcs = RATE_MCS(RATE_MODE_OFDM, 7),
	},
};

static void rt2x00lib_channel(struct ieee80211_channel *entry,
			      const int channel, const int tx_power,
			      const int value)
{
	/* XXX: this assumption about the band is wrong for 802.11j */
	entry->band = channel <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ;
	entry->center_freq = ieee80211_channel_to_frequency(channel,
							    entry->band);
	entry->hw_value = value;
	entry->max_power = tx_power;
	entry->max_antenna_gain = 0xff;
}

static void rt2x00lib_rate(struct ieee80211_rate *entry,
			   const uint16_t index, const struct rt2x00_rate *rate)
{
	entry->flags = 0;
	entry->bitrate = rate->bitrate;
	entry->hw_value = index;
	entry->hw_value_short = index;

	if (rate->flags & DEV_RATE_SHORT_PREAMBLE)
		entry->flags |= IEEE80211_RATE_SHORT_PREAMBLE;
}


static int rt2x00lib_probe_hw_modes(struct rt2x00_dev *rt2x00dev,
				    struct hw_mode_spec *spec)
{
	struct ieee80211_channel *channels;
	struct ieee80211_rate *rates;
	unsigned int num_rates;
	unsigned int i;

    /*
     * Modified to set the local copy of the bands but not populate an ieeehw
     * record since we don't talk to the hw stack
     */

	num_rates = 0;
	if (spec->supported_rates & SUPPORT_RATE_CCK)
		num_rates += 4;
	if (spec->supported_rates & SUPPORT_RATE_OFDM)
		num_rates += 8;

	channels = (struct ieee80211_channel *) kcalloc(spec->num_channels, sizeof(struct ieee80211_channel), GFP_KERNEL);
	if (!channels)
		return -ENOMEM;

	rates = (struct ieee80211_rate *) kcalloc(num_rates, sizeof(struct ieee80211_rate), GFP_KERNEL);
	if (!rates)
		goto exit_free_channels;

	/*
	 * Initialize Rate list.
	 */
	for (i = 0; i < num_rates; i++)
		rt2x00lib_rate(&rates[i], i, rt2x00_get_rate(i));

	/*
	 * Initialize Channel list.
	 */
	for (i = 0; i < spec->num_channels; i++) {
		rt2x00lib_channel(&channels[i],
				  spec->channels[i].channel,
				  spec->channels_info[i].max_power, i);
	}

	/*
	 * Intitialize 802.11b, 802.11g
	 * Rates: CCK, OFDM.
	 * Channels: 2.4 GHz
	 */
	if (spec->supported_bands & SUPPORT_BAND_2GHZ) {
		rt2x00dev->bands[NL80211_BAND_2GHZ].n_channels = 14;
		rt2x00dev->bands[NL80211_BAND_2GHZ].n_bitrates = num_rates;
		rt2x00dev->bands[NL80211_BAND_2GHZ].channels = channels;
		rt2x00dev->bands[NL80211_BAND_2GHZ].bitrates = rates;
	}

	/*
	 * Intitialize 802.11a
	 * Rates: OFDM.
	 * Channels: OFDM, UNII, HiperLAN2.
	 */
	if (spec->supported_bands & SUPPORT_BAND_5GHZ) {
		rt2x00dev->bands[NL80211_BAND_5GHZ].n_channels =
		    spec->num_channels - 14;
		rt2x00dev->bands[NL80211_BAND_5GHZ].n_bitrates =
		    num_rates - 4;
		rt2x00dev->bands[NL80211_BAND_5GHZ].channels = &channels[14];
		rt2x00dev->bands[NL80211_BAND_5GHZ].bitrates = &rates[4];
	}

	return 0;

 exit_free_channels:
	kfree(channels);
	rt2x00_err(rt2x00dev, "Allocation ieee80211 modes failed\n");
	return -ENOMEM;
}

/*
 * RF value list for rt28xx
 * Supports: 2.4 GHz (all) & 5.2 GHz (RF2850 & RF2750)
 */
static const struct rf_channel rf_vals[] = {
	{ 1,  0x18402ecc, 0x184c0786, 0x1816b455, 0x1800510b },
	{ 2,  0x18402ecc, 0x184c0786, 0x18168a55, 0x1800519f },
	{ 3,  0x18402ecc, 0x184c078a, 0x18168a55, 0x1800518b },
	{ 4,  0x18402ecc, 0x184c078a, 0x18168a55, 0x1800519f },
	{ 5,  0x18402ecc, 0x184c078e, 0x18168a55, 0x1800518b },
	{ 6,  0x18402ecc, 0x184c078e, 0x18168a55, 0x1800519f },
	{ 7,  0x18402ecc, 0x184c0792, 0x18168a55, 0x1800518b },
	{ 8,  0x18402ecc, 0x184c0792, 0x18168a55, 0x1800519f },
	{ 9,  0x18402ecc, 0x184c0796, 0x18168a55, 0x1800518b },
	{ 10, 0x18402ecc, 0x184c0796, 0x18168a55, 0x1800519f },
	{ 11, 0x18402ecc, 0x184c079a, 0x18168a55, 0x1800518b },
	{ 12, 0x18402ecc, 0x184c079a, 0x18168a55, 0x1800519f },
	{ 13, 0x18402ecc, 0x184c079e, 0x18168a55, 0x1800518b },
	{ 14, 0x18402ecc, 0x184c07a2, 0x18168a55, 0x18005193 },

	/* 802.11 UNI / HyperLan 2 */
	{ 36, 0x18402ecc, 0x184c099a, 0x18158a55, 0x180ed1a3 },
	{ 38, 0x18402ecc, 0x184c099e, 0x18158a55, 0x180ed193 },
	{ 40, 0x18402ec8, 0x184c0682, 0x18158a55, 0x180ed183 },
	{ 44, 0x18402ec8, 0x184c0682, 0x18158a55, 0x180ed1a3 },
	{ 46, 0x18402ec8, 0x184c0686, 0x18158a55, 0x180ed18b },
	{ 48, 0x18402ec8, 0x184c0686, 0x18158a55, 0x180ed19b },
	{ 52, 0x18402ec8, 0x184c068a, 0x18158a55, 0x180ed193 },
	{ 54, 0x18402ec8, 0x184c068a, 0x18158a55, 0x180ed1a3 },
	{ 56, 0x18402ec8, 0x184c068e, 0x18158a55, 0x180ed18b },
	{ 60, 0x18402ec8, 0x184c0692, 0x18158a55, 0x180ed183 },
	{ 62, 0x18402ec8, 0x184c0692, 0x18158a55, 0x180ed193 },
	{ 64, 0x18402ec8, 0x184c0692, 0x18158a55, 0x180ed1a3 },

	/* 802.11 HyperLan 2 */
	{ 100, 0x18402ec8, 0x184c06b2, 0x18178a55, 0x180ed783 },
	{ 102, 0x18402ec8, 0x184c06b2, 0x18578a55, 0x180ed793 },
	{ 104, 0x18402ec8, 0x185c06b2, 0x18578a55, 0x180ed1a3 },
	{ 108, 0x18402ecc, 0x185c0a32, 0x18578a55, 0x180ed193 },
	{ 110, 0x18402ecc, 0x184c0a36, 0x18178a55, 0x180ed183 },
	{ 112, 0x18402ecc, 0x184c0a36, 0x18178a55, 0x180ed19b },
	{ 116, 0x18402ecc, 0x184c0a3a, 0x18178a55, 0x180ed1a3 },
	{ 118, 0x18402ecc, 0x184c0a3e, 0x18178a55, 0x180ed193 },
	{ 120, 0x18402ec4, 0x184c0382, 0x18178a55, 0x180ed183 },
	{ 124, 0x18402ec4, 0x184c0382, 0x18178a55, 0x180ed193 },
	{ 126, 0x18402ec4, 0x184c0382, 0x18178a55, 0x180ed15b },
	{ 128, 0x18402ec4, 0x184c0382, 0x18178a55, 0x180ed1a3 },
	{ 132, 0x18402ec4, 0x184c0386, 0x18178a55, 0x180ed18b },
	{ 134, 0x18402ec4, 0x184c0386, 0x18178a55, 0x180ed193 },
	{ 136, 0x18402ec4, 0x184c0386, 0x18178a55, 0x180ed19b },
	{ 140, 0x18402ec4, 0x184c038a, 0x18178a55, 0x180ed183 },

	/* 802.11 UNII */
	{ 149, 0x18402ec4, 0x184c038a, 0x18178a55, 0x180ed1a7 },
	{ 151, 0x18402ec4, 0x184c038e, 0x18178a55, 0x180ed187 },
	{ 153, 0x18402ec4, 0x184c038e, 0x18178a55, 0x180ed18f },
	{ 157, 0x18402ec4, 0x184c038e, 0x18178a55, 0x180ed19f },
	{ 159, 0x18402ec4, 0x184c038e, 0x18178a55, 0x180ed1a7 },
	{ 161, 0x18402ec4, 0x184c0392, 0x18178a55, 0x180ed187 },
	{ 165, 0x18402ec4, 0x184c0392, 0x18178a55, 0x180ed197 },
	{ 167, 0x18402ec4, 0x184c03d2, 0x18179855, 0x1815531f },
	{ 169, 0x18402ec4, 0x184c03d2, 0x18179855, 0x18155327 },
	{ 171, 0x18402ec4, 0x184c03d6, 0x18179855, 0x18155307 },
	{ 173, 0x18402ec4, 0x184c03d6, 0x18179855, 0x1815530f },

	/* 802.11 Japan */
	{ 184, 0x15002ccc, 0x1500491e, 0x1509be55, 0x150c0a0b },
	{ 188, 0x15002ccc, 0x15004922, 0x1509be55, 0x150c0a13 },
	{ 192, 0x15002ccc, 0x15004926, 0x1509be55, 0x150c0a1b },
	{ 196, 0x15002ccc, 0x1500492a, 0x1509be55, 0x150c0a23 },
	{ 208, 0x15002ccc, 0x1500493a, 0x1509be55, 0x150c0a13 },
	{ 212, 0x15002ccc, 0x1500493e, 0x1509be55, 0x150c0a1b },
	{ 216, 0x15002ccc, 0x15004982, 0x1509be55, 0x150c0a23 },
};

/*
 * RF value list for rt3xxx
 * Supports: 2.4 GHz (all) & 5.2 GHz (RF3052 & RF3053)
 */
static const struct rf_channel rf_vals_3x[] = {
	{1,  241, 2, 2 },
	{2,  241, 2, 7 },
	{3,  242, 2, 2 },
	{4,  242, 2, 7 },
	{5,  243, 2, 2 },
	{6,  243, 2, 7 },
	{7,  244, 2, 2 },
	{8,  244, 2, 7 },
	{9,  245, 2, 2 },
	{10, 245, 2, 7 },
	{11, 246, 2, 2 },
	{12, 246, 2, 7 },
	{13, 247, 2, 2 },
	{14, 248, 2, 4 },

	/* 802.11 UNI / HyperLan 2 */
	{36, 0x56, 0, 4},
	{38, 0x56, 0, 6},
	{40, 0x56, 0, 8},
	{44, 0x57, 0, 0},
	{46, 0x57, 0, 2},
	{48, 0x57, 0, 4},
	{52, 0x57, 0, 8},
	{54, 0x57, 0, 10},
	{56, 0x58, 0, 0},
	{60, 0x58, 0, 4},
	{62, 0x58, 0, 6},
	{64, 0x58, 0, 8},

	/* 802.11 HyperLan 2 */
	{100, 0x5b, 0, 8},
	{102, 0x5b, 0, 10},
	{104, 0x5c, 0, 0},
	{108, 0x5c, 0, 4},
	{110, 0x5c, 0, 6},
	{112, 0x5c, 0, 8},
	{116, 0x5d, 0, 0},
	{118, 0x5d, 0, 2},
	{120, 0x5d, 0, 4},
	{124, 0x5d, 0, 8},
	{126, 0x5d, 0, 10},
	{128, 0x5e, 0, 0},
	{132, 0x5e, 0, 4},
	{134, 0x5e, 0, 6},
	{136, 0x5e, 0, 8},
	{140, 0x5f, 0, 0},

	/* 802.11 UNII */
	{149, 0x5f, 0, 9},
	{151, 0x5f, 0, 11},
	{153, 0x60, 0, 1},
	{157, 0x60, 0, 5},
	{159, 0x60, 0, 7},
	{161, 0x60, 0, 9},
	{165, 0x61, 0, 1},
	{167, 0x61, 0, 3},
	{169, 0x61, 0, 5},
	{171, 0x61, 0, 7},
	{173, 0x61, 0, 9},
};

/*
 * RF value list for rt3xxx with Xtal20MHz
 * Supports: 2.4 GHz (all) (RF3322)
 */
static const struct rf_channel rf_vals_3x_xtal20[] = {
	{1,    0xE2,	 2,  0x14},
	{2,    0xE3,	 2,  0x14},
	{3,    0xE4,	 2,  0x14},
	{4,    0xE5,	 2,  0x14},
	{5,    0xE6,	 2,  0x14},
	{6,    0xE7,	 2,  0x14},
	{7,    0xE8,	 2,  0x14},
	{8,    0xE9,	 2,  0x14},
	{9,    0xEA,	 2,  0x14},
	{10,   0xEB,	 2,  0x14},
	{11,   0xEC,	 2,  0x14},
	{12,   0xED,	 2,  0x14},
	{13,   0xEE,	 2,  0x14},
	{14,   0xF0,	 2,  0x18},
};

static const struct rf_channel rf_vals_3853[] = {
	{1,  241, 6, 2},
	{2,  241, 6, 7},
	{3,  242, 6, 2},
	{4,  242, 6, 7},
	{5,  243, 6, 2},
	{6,  243, 6, 7},
	{7,  244, 6, 2},
	{8,  244, 6, 7},
	{9,  245, 6, 2},
	{10, 245, 6, 7},
	{11, 246, 6, 2},
	{12, 246, 6, 7},
	{13, 247, 6, 2},
	{14, 248, 6, 4},

	{36, 0x56, 8, 4},
	{38, 0x56, 8, 6},
	{40, 0x56, 8, 8},
	{44, 0x57, 8, 0},
	{46, 0x57, 8, 2},
	{48, 0x57, 8, 4},
	{52, 0x57, 8, 8},
	{54, 0x57, 8, 10},
	{56, 0x58, 8, 0},
	{60, 0x58, 8, 4},
	{62, 0x58, 8, 6},
	{64, 0x58, 8, 8},

	{100, 0x5b, 8, 8},
	{102, 0x5b, 8, 10},
	{104, 0x5c, 8, 0},
	{108, 0x5c, 8, 4},
	{110, 0x5c, 8, 6},
	{112, 0x5c, 8, 8},
	{114, 0x5c, 8, 10},
	{116, 0x5d, 8, 0},
	{118, 0x5d, 8, 2},
	{120, 0x5d, 8, 4},
	{124, 0x5d, 8, 8},
	{126, 0x5d, 8, 10},
	{128, 0x5e, 8, 0},
	{132, 0x5e, 8, 4},
	{134, 0x5e, 8, 6},
	{136, 0x5e, 8, 8},
	{140, 0x5f, 8, 0},

	{149, 0x5f, 8, 9},
	{151, 0x5f, 8, 11},
	{153, 0x60, 8, 1},
	{157, 0x60, 8, 5},
	{159, 0x60, 8, 7},
	{161, 0x60, 8, 9},
	{165, 0x61, 8, 1},
	{167, 0x61, 8, 3},
	{169, 0x61, 8, 5},
	{171, 0x61, 8, 7},
	{173, 0x61, 8, 9},
};

static const struct rf_channel rf_vals_5592_xtal20[] = {
	/* Channel, N, K, mod, R */
	{1, 482, 4, 10, 3},
	{2, 483, 4, 10, 3},
	{3, 484, 4, 10, 3},
	{4, 485, 4, 10, 3},
	{5, 486, 4, 10, 3},
	{6, 487, 4, 10, 3},
	{7, 488, 4, 10, 3},
	{8, 489, 4, 10, 3},
	{9, 490, 4, 10, 3},
	{10, 491, 4, 10, 3},
	{11, 492, 4, 10, 3},
	{12, 493, 4, 10, 3},
	{13, 494, 4, 10, 3},
	{14, 496, 8, 10, 3},
	{36, 172, 8, 12, 1},
	{38, 173, 0, 12, 1},
	{40, 173, 4, 12, 1},
	{42, 173, 8, 12, 1},
	{44, 174, 0, 12, 1},
	{46, 174, 4, 12, 1},
	{48, 174, 8, 12, 1},
	{50, 175, 0, 12, 1},
	{52, 175, 4, 12, 1},
	{54, 175, 8, 12, 1},
	{56, 176, 0, 12, 1},
	{58, 176, 4, 12, 1},
	{60, 176, 8, 12, 1},
	{62, 177, 0, 12, 1},
	{64, 177, 4, 12, 1},
	{100, 183, 4, 12, 1},
	{102, 183, 8, 12, 1},
	{104, 184, 0, 12, 1},
	{106, 184, 4, 12, 1},
	{108, 184, 8, 12, 1},
	{110, 185, 0, 12, 1},
	{112, 185, 4, 12, 1},
	{114, 185, 8, 12, 1},
	{116, 186, 0, 12, 1},
	{118, 186, 4, 12, 1},
	{120, 186, 8, 12, 1},
	{122, 187, 0, 12, 1},
	{124, 187, 4, 12, 1},
	{126, 187, 8, 12, 1},
	{128, 188, 0, 12, 1},
	{130, 188, 4, 12, 1},
	{132, 188, 8, 12, 1},
	{134, 189, 0, 12, 1},
	{136, 189, 4, 12, 1},
	{138, 189, 8, 12, 1},
	{140, 190, 0, 12, 1},
	{149, 191, 6, 12, 1},
	{151, 191, 10, 12, 1},
	{153, 192, 2, 12, 1},
	{155, 192, 6, 12, 1},
	{157, 192, 10, 12, 1},
	{159, 193, 2, 12, 1},
	{161, 193, 6, 12, 1},
	{165, 194, 2, 12, 1},
	{184, 164, 0, 12, 1},
	{188, 164, 4, 12, 1},
	{192, 165, 8, 12, 1},
	{196, 166, 0, 12, 1},
};

static const struct rf_channel rf_vals_5592_xtal40[] = {
	/* Channel, N, K, mod, R */
	{1, 241, 2, 10, 3},
	{2, 241, 7, 10, 3},
	{3, 242, 2, 10, 3},
	{4, 242, 7, 10, 3},
	{5, 243, 2, 10, 3},
	{6, 243, 7, 10, 3},
	{7, 244, 2, 10, 3},
	{8, 244, 7, 10, 3},
	{9, 245, 2, 10, 3},
	{10, 245, 7, 10, 3},
	{11, 246, 2, 10, 3},
	{12, 246, 7, 10, 3},
	{13, 247, 2, 10, 3},
	{14, 248, 4, 10, 3},
	{36, 86, 4, 12, 1},
	{38, 86, 6, 12, 1},
	{40, 86, 8, 12, 1},
	{42, 86, 10, 12, 1},
	{44, 87, 0, 12, 1},
	{46, 87, 2, 12, 1},
	{48, 87, 4, 12, 1},
	{50, 87, 6, 12, 1},
	{52, 87, 8, 12, 1},
	{54, 87, 10, 12, 1},
	{56, 88, 0, 12, 1},
	{58, 88, 2, 12, 1},
	{60, 88, 4, 12, 1},
	{62, 88, 6, 12, 1},
	{64, 88, 8, 12, 1},
	{100, 91, 8, 12, 1},
	{102, 91, 10, 12, 1},
	{104, 92, 0, 12, 1},
	{106, 92, 2, 12, 1},
	{108, 92, 4, 12, 1},
	{110, 92, 6, 12, 1},
	{112, 92, 8, 12, 1},
	{114, 92, 10, 12, 1},
	{116, 93, 0, 12, 1},
	{118, 93, 2, 12, 1},
	{120, 93, 4, 12, 1},
	{122, 93, 6, 12, 1},
	{124, 93, 8, 12, 1},
	{126, 93, 10, 12, 1},
	{128, 94, 0, 12, 1},
	{130, 94, 2, 12, 1},
	{132, 94, 4, 12, 1},
	{134, 94, 6, 12, 1},
	{136, 94, 8, 12, 1},
	{138, 94, 10, 12, 1},
	{140, 95, 0, 12, 1},
	{149, 95, 9, 12, 1},
	{151, 95, 11, 12, 1},
	{153, 96, 1, 12, 1},
	{155, 96, 3, 12, 1},
	{157, 96, 5, 12, 1},
	{159, 96, 7, 12, 1},
	{161, 96, 9, 12, 1},
	{165, 97, 1, 12, 1},
	{184, 82, 0, 12, 1},
	{188, 82, 4, 12, 1},
	{192, 82, 8, 12, 1},
	{196, 83, 0, 12, 1},
};

static const struct rf_channel rf_vals_7620[] = {
	{1, 0x50, 0x99, 0x99, 1},
	{2, 0x50, 0x44, 0x44, 2},
	{3, 0x50, 0xEE, 0xEE, 2},
	{4, 0x50, 0x99, 0x99, 3},
	{5, 0x51, 0x44, 0x44, 0},
	{6, 0x51, 0xEE, 0xEE, 0},
	{7, 0x51, 0x99, 0x99, 1},
	{8, 0x51, 0x44, 0x44, 2},
	{9, 0x51, 0xEE, 0xEE, 2},
	{10, 0x51, 0x99, 0x99, 3},
	{11, 0x52, 0x44, 0x44, 0},
	{12, 0x52, 0xEE, 0xEE, 0},
	{13, 0x52, 0x99, 0x99, 1},
	{14, 0x52, 0x33, 0x33, 3},
};

static int rt2800_probe_hw_mode(struct rt2x00_dev *rt2x00dev)
{
	struct hw_mode_spec *spec = &rt2x00dev->spec;
	struct channel_info *info;
	unsigned int tx_chains, rx_chains;
	uint32_t reg;

    /* 
     * Gutted for userspace mode 
     * */

	/*
	 * Initialize hw_mode information.
	 */
	spec->supported_rates = SUPPORT_RATE_CCK | SUPPORT_RATE_OFDM;

	switch (rt2x00dev->chip.rf) {
	case RF2720:
	case RF2820:
		spec->num_channels = 14;
		spec->channels = rf_vals;
		break;

	case RF2750:
	case RF2850:
		spec->num_channels = ARRAY_SIZE(rf_vals);
		spec->channels = rf_vals;
		break;

	case RF2020:
	case RF3020:
	case RF3021:
	case RF3022:
	case RF3070:
	case RF3290:
	case RF3320:
	case RF3322:
	case RF5350:
	case RF5360:
	case RF5362:
	case RF5370:
	case RF5372:
	case RF5390:
	case RF5392:
		spec->num_channels = 14;
		if (rt2800_clk_is_20mhz(rt2x00dev))
			spec->channels = rf_vals_3x_xtal20;
		else
			spec->channels = rf_vals_3x;
		break;

	case RF7620:
		spec->num_channels = ARRAY_SIZE(rf_vals_7620);
		spec->channels = rf_vals_7620;
		break;

	case RF3052:
	case RF3053:
		spec->num_channels = ARRAY_SIZE(rf_vals_3x);
		spec->channels = rf_vals_3x;
		break;

	case RF3853:
		spec->num_channels = ARRAY_SIZE(rf_vals_3853);
		spec->channels = rf_vals_3853;
		break;

	case RF5592:
		reg = rt2800_register_read(rt2x00dev, MAC_DEBUG_INDEX);
		if (rt2x00_get_field32(reg, MAC_DEBUG_INDEX_XTAL)) {
			spec->num_channels = ARRAY_SIZE(rf_vals_5592_xtal40);
			spec->channels = rf_vals_5592_xtal40;
		} else {
			spec->num_channels = ARRAY_SIZE(rf_vals_5592_xtal20);
			spec->channels = rf_vals_5592_xtal20;
		}
		break;
	}

	if (WARN_ON_ONCE(!spec->channels))
		return -ENODEV;

	spec->supported_bands = SUPPORT_BAND_2GHZ;
	if (spec->num_channels > 14)
		spec->supported_bands |= SUPPORT_BAND_5GHZ;

	/*
	 * Initialize HT information.
	 */
	if (!rt2x00_rf(rt2x00dev, RF2020))
		spec->ht.ht_supported = true;
	else
		spec->ht.ht_supported = false;

	spec->ht.cap =
	    IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
	    IEEE80211_HT_CAP_GRN_FLD |
	    IEEE80211_HT_CAP_SGI_20 |
	    IEEE80211_HT_CAP_SGI_40;

	tx_chains = rt2x00dev->default_ant.tx_chain_num;
	rx_chains = rt2x00dev->default_ant.rx_chain_num;

	if (tx_chains >= 2)
		spec->ht.cap |= IEEE80211_HT_CAP_TX_STBC;

	spec->ht.cap |= rx_chains << IEEE80211_HT_CAP_RX_STBC_SHIFT;

	spec->ht.ampdu_factor = (rx_chains > 1) ? 3 : 2;
	spec->ht.ampdu_density = 4;
	spec->ht.mcs.tx_params = IEEE80211_HT_MCS_TX_DEFINED;
	if (tx_chains != rx_chains) {
		spec->ht.mcs.tx_params |= IEEE80211_HT_MCS_TX_RX_DIFF;
		spec->ht.mcs.tx_params |=
		    (tx_chains - 1) << IEEE80211_HT_MCS_TX_MAX_STREAMS_SHIFT;
	}

	switch (rx_chains) {
	case 3:
		spec->ht.mcs.rx_mask[2] = 0xff;
		/* fall through */
	case 2:
		spec->ht.mcs.rx_mask[1] = 0xff;
		/* fall through */
	case 1:
		spec->ht.mcs.rx_mask[0] = 0xff;
		spec->ht.mcs.rx_mask[4] = 0x1; /* MCS32 */
		break;
	}

	/*
	 * Create channel information array
	 */
	info = kcalloc(spec->num_channels, sizeof(struct channel_info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	spec->channels_info = info;

	switch (rt2x00dev->chip.rf) {
	case RF2020:
	case RF3020:
	case RF3021:
	case RF3022:
	case RF3320:
	case RF3052:
	case RF3053:
	case RF3070:
	case RF3290:
	case RF3853:
	case RF5350:
	case RF5360:
	case RF5362:
	case RF5370:
	case RF5372:
	case RF5390:
	case RF5392:
	case RF5592:
	case RF7620:
		__set_bit(CAPABILITY_VCO_RECALIBRATION, &rt2x00dev->cap_flags);
		break;
	}

	return 0;
}

struct rt2800usb_userspace_firmware {
    uint8_t *data;
    size_t size;
};

int rt2800usb_userspace_load_firmware(struct rt2x00_dev *rt2x00dev, 
        struct rt2800usb_userspace_firmware **fw) {
    struct userspace_wifi_context *userspace_context =
        (struct userspace_wifi_context *) rt2x00dev->userspace_context;

    int retval;

    *fw = (struct rt2800usb_userspace_firmware *) malloc(sizeof(struct rt2800usb_userspace_firmware));

    if (*fw == NULL) {
        rt2x00_err(rt2x00dev, "Unable to allocate memory to read firmware file.");
        return -ENOMEM;
    }

    retval = (*userspace_context->load_firmware_file)(userspace_context,
            FIRMWARE_RT2870,
            NULL, 0,
            &(*fw)->data, &(*fw)->size);

    if (retval != 0) {
        rt2x00_err(rt2x00dev, "Could not load firmware %s, cannot continue.", FIRMWARE_RT2870);
        return -1;
    }

	rt2x00_info(rt2x00dev, "Firmware detected - version: %d.%d\n",
		    (*fw)->data[(*fw)->size - 4], (*fw)->data[(*fw)->size - 3]);

	retval = rt2x00dev->ops->lib->check_firmware(rt2x00dev, (*fw)->data, (*fw)->size);
	switch (retval) {
	case FW_OK:
		break;
	case FW_BAD_CRC:
		rt2x00_err(rt2x00dev, "Firmware checksum error\n");
		goto exit;
	case FW_BAD_LENGTH:
		rt2x00_err(rt2x00dev, "Invalid firmware file length (len=%zu)\n",
			   (*fw)->size);
		goto exit;
	case FW_BAD_VERSION:
		rt2x00_err(rt2x00dev, "Current firmware does not support detected chipset\n");
		goto exit;
    }

    return (*fw)->size;

exit:
    free((*fw)->data);
    free(*fw);
    *fw = NULL;
    return -EINVAL;
}

void rt2800usb_userspace_free_firmware(struct rt2800usb_userspace_firmware *fw) {
    if (!fw)
        return;

    if (fw->data)
        free(fw->data);

    free(fw);
}


static const struct rt2800_ops rt2800usb_rt2800_ops = {
    .register_read		= rt2x00usb_register_read,
    .register_read_lock	= rt2x00usb_register_read_lock,
    .register_write		= rt2x00usb_register_write,
    .register_write_lock	= rt2x00usb_register_write_lock,
    .register_multiread	= rt2x00usb_register_multiread,
    .register_multiwrite	= rt2x00usb_register_multiwrite,
    .regbusy_read		= rt2x00usb_regbusy_read,
    .read_eeprom		= rt2800usb_read_eeprom,
    .drv_write_firmware	= rt2800usb_write_firmware,
    .drv_init_registers	= rt2800usb_init_registers,
};

static const struct rt2x00lib_ops rt2800usb_rt2x00_ops = {
    .get_firmware_name	= rt2800usb_get_firmware_name,
    .check_firmware		= rt2800_check_firmware,
    .load_firmware		= rt2800_load_firmware,
    .initialize		= rt2x00usb_initialize,
    .set_device_state	= rt2800usb_set_device_state,
    .rfkill_poll		= rt2800_rfkill_poll,
    .link_stats		= rt2800_link_stats,
    .reset_tuner		= rt2800_reset_tuner,
    .link_tuner		= rt2800_link_tuner,
    .vco_calibration	= rt2800_vco_calibration,
    .config_filter		= rt2800_config_filter,
    .config_intf		= rt2800_config_intf,
    .config_erp		= rt2800_config_erp,
    .config_ant		= rt2800_config_ant,
    .config			= rt2800_config,
    .start_queue    = rt2800usb_start_queue,
    .stop_queue     = rt2800usb_stop_queue
};

static const struct rt2x00_ops rt2800usb_ops = {
	.drv_data_size		= sizeof(struct rt2800_drv_data),
	.max_ap_intf		= 8,
	.eeprom_size		= EEPROM_SIZE,
	.rf_size		= RF_SIZE,
	.tx_queues		= NUM_TX_QUEUES,
	.lib			= &rt2800usb_rt2x00_ops,
	.drv			= &rt2800usb_rt2800_ops,
#ifdef CONFIG_RT2X00_LIB_DEBUGFS
	.debugfs		= &rt2800_rt2x00debug,
#endif /* CONFIG_RT2X00_LIB_DEBUGFS */
};

/*
 * Userspace channel set function
 */
int rt2800usb_userspace_set_channel(struct userspace_wifi_dev *dev, int channel, enum nl80211_chan_width width) {
    struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *) dev->dev_data;
    struct ieee80211_conf dot11conf;
    enum nl80211_band band;

    memset(&dot11conf, 0, sizeof(struct ieee80211_conf));
    dot11conf.chandef.width = width;

    /*
     * TODO handle 5ghz 
     */
    if (channel >= 1 && channel <= 14) {
        dot11conf.chandef.chan = &rt2x00dev->bands[NL80211_BAND_2GHZ].channels[channel - 1];
        band = NL80211_BAND_2GHZ;
    } else {
        return -EINVAL;
    }

    /* Queue must be stopped to set the channel state */
    rt2800usb_stop_queue(rt2x00dev);

    /* Try to set the channel */
    rt2x00lib_config(rt2x00dev, &dot11conf, IEEE80211_CONF_CHANGE_CHANNEL | IEEE80211_CONF_CHANGE_MONITOR);
	rt2x00lib_config_antenna(rt2x00dev, rt2x00dev->default_ant);

    /* Set the channel copy */
    rt2x00dev->rf_channel = channel;
    rt2x00dev->rf_band = band;

    /* Try to start the RX engine */
    rt2800usb_start_queue(rt2x00dev);

    return 0;
}

/*
 * Userspace LED control function
 */
int rt2800usb_userspace_set_led(struct userspace_wifi_dev *dev, bool enable) {
    struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *) dev->dev_data;

    unsigned int ledmode =
        rt2x00_get_field16(rt2x00dev->led_mcu_reg,
                EEPROM_FREQ_LED_MODE);
    rt2800_mcu_request(rt2x00dev, MCU_LED, 0xff, ledmode, enable ? 0x60 : 0x20);

    return 1;
}

/* 
 * From rt2800lib
 */
void rt2800_get_txwi_rxwi_size(struct rt2x00_dev *rt2x00dev,
			       unsigned short *txwi_size,
			       unsigned short *rxwi_size)
{
	switch (rt2x00dev->chip.rt) {
	case RT3593:
	case RT3883:
		*txwi_size = TXWI_DESC_SIZE_4WORDS;
		*rxwi_size = RXWI_DESC_SIZE_5WORDS;
		break;

	case RT5592:
	case RT6352:
		*txwi_size = TXWI_DESC_SIZE_5WORDS;
		*rxwi_size = RXWI_DESC_SIZE_6WORDS;
		break;

	default:
		*txwi_size = TXWI_DESC_SIZE_4WORDS;
		*rxwi_size = RXWI_DESC_SIZE_4WORDS;
		break;
	}
}

/**
 * _rt2x00_desc_read - Read a word from the hardware descriptor.
 * @desc: Base descriptor address
 * @word: Word index from where the descriptor should be read.
 */
static inline ___le32 _rt2x00_desc_read(___le32 *desc, const uint8_t word)
{
	return desc[word];
}

/**
 * rt2x00_desc_read - Read a word from the hardware descriptor, this
 * function will take care of the byte ordering.
 * @desc: Base descriptor address
 * @word: Word index from where the descriptor should be read.
 */
static inline uint32_t rt2x00_desc_read(___le32 *desc, const uint8_t word)
{
	return le32_to_cpu(_rt2x00_desc_read(desc, word));
}

static int rt2800_agc_to_rssi(struct rt2x00_dev *rt2x00dev, uint32_t rxwi_w2)
{
	int8_t rssi0 = rt2x00_get_field32(rxwi_w2, RXWI_W2_RSSI0);
	int8_t rssi1 = rt2x00_get_field32(rxwi_w2, RXWI_W2_RSSI1);
	int8_t rssi2 = rt2x00_get_field32(rxwi_w2, RXWI_W2_RSSI2);
	uint16_t eeprom;
	uint8_t offset0;
	uint8_t offset1;
	uint8_t offset2;

	if (rt2x00dev->curr_band == NL80211_BAND_2GHZ) {
		eeprom = rt2800_eeprom_read(rt2x00dev, EEPROM_RSSI_BG);
		offset0 = rt2x00_get_field16(eeprom, EEPROM_RSSI_BG_OFFSET0);
		offset1 = rt2x00_get_field16(eeprom, EEPROM_RSSI_BG_OFFSET1);
		eeprom = rt2800_eeprom_read(rt2x00dev, EEPROM_RSSI_BG2);
		offset2 = rt2x00_get_field16(eeprom, EEPROM_RSSI_BG2_OFFSET2);
	} else {
		eeprom = rt2800_eeprom_read(rt2x00dev, EEPROM_RSSI_A);
		offset0 = rt2x00_get_field16(eeprom, EEPROM_RSSI_A_OFFSET0);
		offset1 = rt2x00_get_field16(eeprom, EEPROM_RSSI_A_OFFSET1);
		eeprom = rt2800_eeprom_read(rt2x00dev, EEPROM_RSSI_A2);
		offset2 = rt2x00_get_field16(eeprom, EEPROM_RSSI_A2_OFFSET2);
	}

	/*
	 * Convert the value from the descriptor into the RSSI value
	 * If the value in the descriptor is 0, it is considered invalid
	 * and the default (extremely low) rssi value is assumed
	 */
	rssi0 = (rssi0) ? (-12 - offset0 - rt2x00dev->lna_gain - rssi0) : -128;
	rssi1 = (rssi1) ? (-12 - offset1 - rt2x00dev->lna_gain - rssi1) : -128;
	rssi2 = (rssi2) ? (-12 - offset2 - rt2x00dev->lna_gain - rssi2) : -128;

	/*
	 * mac80211 only accepts a single RSSI value. Calculating the
	 * average doesn't deliver a fair answer either since -60:-60 would
	 * be considered equally good as -50:-70 while the second is the one
	 * which gives less energy...
	 */
	rssi0 = max(rssi0, rssi1);
	return (int)max(rssi0, rssi2);
}

/* Function like the rt2x00 pull, but return the amount of data the caller
 * needs to offset the buffer by */
unsigned int rt2x00queue_remove_l2pad(uint8_t *buf, unsigned int buf_len, unsigned int hdr_len)
{
	unsigned int l2pad = (buf_len > hdr_len) ? L2PAD_SIZE(hdr_len) : 0;

	if (!l2pad)
		return buf_len;

	memmove(buf + l2pad, buf, hdr_len);
    return l2pad;
}

/* 
 * LibUSB usb transfer completion
 * RXI parsing extracted from rt2800usb_fill_rxdone and rt2800_process_rxwi
 */
void rt2800usb_libusb_transfer_fn(struct libusb_transfer *transfer) {
    struct userspace_wifi_dev *dev = (struct userspace_wifi_dev *) transfer->user_data;
    struct rt2x00_dev * rt2x00dev = (struct rt2x00_dev *) (dev)->dev_data;

    /*
     * Working buffer ptr we move around while emulating skb_trim and skb_pull
     */
    unsigned char *workbuf = transfer->buffer;
    unsigned int workbuf_len = transfer->actual_length;

	___le32 *rxi = (___le32 *) workbuf;
	___le32 *rxd;
	uint32_t word;

	unsigned int rx_pkt_len;

    struct userspace_wifi_rx_signal rx_signal;

    unsigned int mpdu_sz;

    unsigned int pad = 0;

    unsigned int header_len = 0;

    if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
        /* Timeout errors get re-submitted, other errors get bounced up */

        if (transfer->status == LIBUSB_TRANSFER_NO_DEVICE)  {
            rt2x00_err(rt2x00dev, "Radio request failed: %d %s - device no longer available",
                    transfer->status, libusb_error_name(transfer->status));
        } else if (transfer->status != LIBUSB_TRANSFER_TIMED_OUT)  {
            rt2x00_err(rt2x00dev, "Radio request failed: %d %s", 
                    transfer->status, libusb_error_name(transfer->status));
        }

        userspace_wifi_lock(dev->context);
        if (dev->usb_transfer_active)
            libusb_submit_transfer(transfer);
        userspace_wifi_unlock(dev->context);
        return;
    }

	/*
	 * RX frame format is :
	 * | RXINFO | RXWI | header | L2 pad | payload | pad | RXD | USB pad |
	 *          |<------------ rx_pkt_len -------------->|
	 */

    if (transfer->actual_length < RXINFO_DESC_SIZE + rt2x00dev->rxwi_size) {
        /*
         * Silently ignore and re-queue on runt transfers
         */

        userspace_wifi_lock(dev->context);
        if (dev->usb_transfer_active)
            libusb_submit_transfer(transfer);
        userspace_wifi_unlock(dev->context);
        return;
    }

    memset(&rx_signal, 0, sizeof(struct userspace_wifi_rx_signal));

    rx_signal.channel = rt2x00dev->rf_channel;
    rx_signal.band = rt2x00dev->rf_band;

    /*
     * Get packet length of RXWI + payload + pad from the header of the packet
     */
	word = rt2x00_desc_read(rxi, 0);
	rx_pkt_len = rt2x00_get_field32(word, RXINFO_W0_USB_DMA_RX_PKT_LEN);

    if (rx_pkt_len == 0 || rx_pkt_len > (transfer->actual_length - RXINFO_DESC_SIZE)) {
        /*
         * Ignore errors in packet size and re-queue
         */

        userspace_wifi_lock(dev->context);
        if (dev->usb_transfer_active)
            libusb_submit_transfer(transfer);
        userspace_wifi_unlock(dev->context);
        return;
    }

    workbuf = workbuf + RXINFO_DESC_SIZE;
    workbuf_len -= RXINFO_DESC_SIZE;

	rxd = (___le32 *)(workbuf + rx_pkt_len);

	/*
	 * It is now safe to read the descriptor on all architectures.
	 */
	word = rt2x00_desc_read((___le32 *) rxd, 0);

	if (rt2x00_get_field32(word, RXD_W0_L2PAD))
        pad = 1;

	if (rt2x00_get_field32(word, RXD_W0_CRC_ERROR))
        rx_signal.crc_valid = false;
    else
        rx_signal.crc_valid = true;

	/*
	 * Remove RXD descriptor from end of buffer.
	 */
    workbuf_len = rx_pkt_len;

    /*
     * Remove the padding from the end of the buffer
    workbuf_len -= pad;
     */

    rxi = (___le32 *) workbuf;

	word = rt2x00_desc_read(rxi, 0);
	mpdu_sz = rt2x00_get_field32(word, RXWI_W0_MPDU_TOTAL_BYTE_COUNT);

	word = rt2x00_desc_read(rxi, 1);

	if (rt2x00_get_field32(word, RXWI_W1_SHORT_GI)) {
        rx_signal.short_gi = true;
	}

	if (rt2x00_get_field32(word, RXWI_W1_BW)) {
        rx_signal.chan_width = NL80211_CHAN_WIDTH_40;
	} else {
        rx_signal.chan_width = NL80211_CHAN_WIDTH_20_NOHT;
    }

	/*
	 * Detect RX rate, always use MCS as signal type.
	 */
    rx_signal.mcs = rt2x00_get_field32(word, RXWI_W1_MCS);

	/*
	 * Mask of 0x8 bit to remove the short preamble flag.
	 */
    if (rt2x00_get_field32(word, RXWI_W1_PHYMODE) == RATE_MODE_CCK) 
        rx_signal.mcs &= ~0x8;

    word = rt2x00_desc_read(rxi, 2);

	/*
	 * Convert descriptor AGC value to RSSI value.
	 */
    rx_signal.signal = rt2800_agc_to_rssi(rt2x00dev, word);

    /*
     * Remove the rxwi header
     */
    workbuf = workbuf + rt2x00dev->rxwi_size;
    workbuf_len -= rt2x00dev->rxwi_size;

    if (mpdu_sz > workbuf_len) {
        /*
         * If we get a mpdu that can't fit in our rx, throw it out and re-queue a command
         */
        userspace_wifi_lock(dev->context);
        if (dev->usb_transfer_active)
            libusb_submit_transfer(transfer);
        userspace_wifi_unlock(dev->context);
    }

    /*
     * The 802.11 header needs to be padded to 4 bytes; make sure it is.
     */
    header_len = ieee80211_get_hdrlen_from_buf(workbuf, mpdu_sz);
    if (header_len < workbuf_len && pad) {
        pad = rt2x00queue_remove_l2pad(workbuf, workbuf_len, header_len);
        workbuf = workbuf + pad;
    }

    /*
     * Pass the data on to a callback.  We use a stack-allocated signal because this
     * is all iterative.
     */
    if (dev->context->handle_packet_rx) {
        dev->context->handle_packet_rx(dev->context, dev, &rx_signal, workbuf, mpdu_sz);
    }

    /* 
     * Resubmit the request
     */
    userspace_wifi_lock(dev->context);
    if (dev->usb_transfer_active)
        libusb_submit_transfer(transfer);
    userspace_wifi_unlock(dev->context);
}

int rt2800usb_userspace_start_capture(struct userspace_wifi_dev *dev) {
    struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *) (dev)->dev_data;

    /* Set up the bulk transfer */
    if (dev->usb_transfer_buffer == NULL) {
        dev->usb_transfer_buffer = (unsigned char *) malloc(4000);
        if (dev->usb_transfer_buffer == NULL)
            return -ENOMEM;
    }

    if (dev->usb_transfer == NULL) {
        dev->usb_transfer = libusb_alloc_transfer(0);
    }

    libusb_fill_bulk_transfer(dev->usb_transfer,
            rt2x00dev->dev,
            rt2x00dev->usb_bulk_in_endp,
            dev->usb_transfer_buffer,
            4000,
            &rt2800usb_libusb_transfer_fn,
            dev,
            500);

    rt2800usb_start_queue(rt2x00dev);

    userspace_wifi_lock(dev->context);
    dev->usb_transfer_active = true;
    libusb_submit_transfer(dev->usb_transfer);
    userspace_wifi_unlock(dev->context);

    return 0;
}

void rt2800usb_userspace_stop_capture(struct userspace_wifi_dev *dev) {
    struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *) (dev)->dev_data;

    userspace_wifi_lock(dev->context);

    rt2800usb_stop_queue(rt2x00dev);

    dev->usb_transfer_active = false;
    libusb_cancel_transfer(dev->usb_transfer);

    userspace_wifi_unlock(dev->context);
}

int rt2800usb_open_device(struct userspace_wifi_probe_dev *dev, 
        struct userspace_wifi_dev **udev) {

    struct rt2x00_dev *rt2x00dev;
    int r;
    struct rt2800usb_userspace_firmware *firmware;

    *udev = (struct userspace_wifi_dev *) malloc(sizeof(struct userspace_wifi_dev));

    if (*udev == NULL)
        return -ENOMEM;

    memset(*udev, 0, sizeof(struct userspace_wifi_dev));

    (*udev)->context = dev->context;

    (*udev)->dev_data = malloc(sizeof(struct rt2x00_dev));

    if ((*udev)->dev_data == NULL) {
        free(*udev);
        return -ENOMEM;
    }

    (*udev)->set_channel = rt2800usb_userspace_set_channel;
    (*udev)->set_led = rt2800usb_userspace_set_led;
    (*udev)->start_capture = rt2800usb_userspace_start_capture;
    (*udev)->stop_capture = rt2800usb_userspace_stop_capture;

    /*
     * Populate the 2x00dev record w/ ops, copies of pointers to
     * structures we need to pull in on deeper levels like usb and
     * userspace context, etc
     */
    rt2x00dev = (struct rt2x00_dev *) (*udev)->dev_data;

    memset(rt2x00dev, 0, sizeof(struct rt2x00_dev));

    rt2x00dev->userspace_dev = udev;

    rt2x00dev->libusb_context = dev->context->libusb_context;
    rt2x00dev->userspace_context = dev->context;
    pthread_mutex_init(&rt2x00dev->usb_control_mutex, NULL);
    pthread_cond_init(&rt2x00dev->usb_control_cond, NULL);
    rt2x00dev->ops = &rt2800usb_ops;
    rt2x00dev->base_dev = dev->dev;

	rt2x00_set_chip_intf(rt2x00dev, RT2X00_CHIP_INTF_USB);

    /*
     * Allocate the low level cache ops 
     */
    r = rt2x00usb_alloc_reg(rt2x00dev);

    if (r != 0) {
        free(rt2x00dev);
        free(*udev);
        return r;
    }

    /* 
     * Open the usb device, disconnecting any kernel drivers and other attachments
     */
    r = libusb_open(rt2x00dev->base_dev, &rt2x00dev->dev);

    if (r < 0) {
        rt2x00_err(rt2x00dev, "Failed to open device: %s\n", 
                libusb_error_name(r));
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return -EPIPE;
    }

    libusb_set_auto_detach_kernel_driver(rt2x00dev->dev, 1);
    r = libusb_claim_interface(rt2x00dev->dev, 0);

    if (r != LIBUSB_SUCCESS) {
        rt2x00_err(rt2x00dev, "Failed to claim device: %s\n",
                libusb_error_name(r));
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return -EPIPE;
    }

    /*
     * initialize the lowlevel 2x00 and find the endpoints 
     */
    r = rt2x00usb_initialize(rt2x00dev);

    if (r != 0) {
        rt2x00_err(rt2x00dev, "Failed to initialize rt2x00 layer\n");
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    }

    /* 
     * flag the device as present
     */
    set_bit(DEVICE_STATE_PRESENT, &rt2x00dev->flags);

	r = rt2800_probe_rt(rt2x00dev);
    if (r != 0) {
        rt2x00_err(rt2x00dev, "Failed to probe rt info\n");
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    }

    /*
     * Check if we're in autorun mode
     */
    r = rt2800usb_autorun_detect(rt2x00dev);

	/*
	 * Allocate eeprom data.
	 */
    memset(rt2x00dev->eeprom, 0, EEPROM_SIZE);
	r = rt2800_validate_eeprom(rt2x00dev);
	if (r) {
        rt2x00_err(rt2x00dev, "Failed to validate eeprom\n");
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    }

	r = rt2800_init_eeprom(rt2x00dev);
	if (r) {
        rt2x00_err(rt2x00dev, "Failed to init eeprom\n");
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    }

    /* Propogate the mac up */
    memcpy((*udev)->dev_mac, rt2x00dev->mac, 6);

    /* Propogate the serial from the probe device to the final */
    memcpy((*udev)->usb_serial, dev->usb_serial, 64);

#if 0
    for (unsigned int x = 0; x < EEPROM_SIZE; x++)
        printf("%02x ", ((uint8_t *) rt2x00dev->eeprom) [x] & 0xFF);
    printf("\n");

    printf("Radio MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            rt2x00dev->mac[0], rt2x00dev->mac[1], rt2x00dev->mac[2],
            rt2x00dev->mac[3], rt2x00dev->mac[4], rt2x00dev->mac[5]);
#endif

    /* 
     * Load and check our firmware file
     */
    r = rt2800usb_userspace_load_firmware(rt2x00dev, &firmware);
    if (r < 0) {
        rt2x00_err(rt2x00dev, "Failed to load firmware file on host\n");
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    }

    /*
     * Load it into the device
     */
    r = rt2800_load_firmware(rt2x00dev, firmware->data, firmware->size);
    if (r < 0) {
        rt2x00_err(rt2x00dev, "Firmware load failed: %d %s\n", r, strerror(r));
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    } else {
        rt2x00_info(rt2x00dev, "Firmware load succeeded!\n");
    }

    /*
     * Power on the MCU
     */
    r = rt2800usb_set_device_state(rt2x00dev, STATE_AWAKE);
    if (r < 0) {
        rt2x00_err(rt2x00dev, "Failed to awaken radio\n");
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    } else {
        rt2x00_info(rt2x00dev, "Radio woken up!\n");
    }

    /*
     * Startup the device
     */
    r = rt2x00lib_start(rt2x00dev);
    if (r < 0) {
        rt2x00_err(rt2x00dev, "Failed to start device\n");
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    } else {
        rt2x00_info(rt2x00dev, "Device started!\n");
    }

    /* 
     * Enable the radio
     */
    r = rt2800usb_enable_radio(rt2x00dev);
    if (r < 0) {
        rt2x00_err(rt2x00dev, "Failed to enable the radio\n");
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    } else {
        rt2x00_info(rt2x00dev, "Radio enabled!\n");
    }

	rt2800_get_txwi_rxwi_size(rt2x00dev, &rt2x00dev->txwi_size, &rt2x00dev->rxwi_size);

    /*
     * probe hw modes
     */
    r = rt2800_probe_hw_mode(rt2x00dev);
    if (r < 0) {
        rt2x00_err(rt2x00dev, "Failed to probe 2800_hw_mode\n");
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    } else {
        rt2x00_info(rt2x00dev, "RT2800 Hw modes probed!\n");
    }

    r = rt2x00lib_probe_hw_modes(rt2x00dev, &rt2x00dev->spec);
    if (r < 0) {
        rt2x00_err(rt2x00dev, "Failed to probe 2x00_hw_modes\n");
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    } else {
        rt2x00_info(rt2x00dev, "RT2x00 Hw modes probed!\n");
    }

    /* Radio must be enabled, but rx disabled, to set the channel and antenna values */
    rt2800usb_stop_queue(rt2x00dev);

    struct ieee80211_hw hw;
    memset(&hw, 0, sizeof(struct ieee80211_hw));

    hw.priv = rt2x00dev;

    struct ieee80211_vif vif;
    memset(&vif, 0, sizeof(struct ieee80211_vif));
    vif.type = NL80211_IFTYPE_MONITOR;
    memcpy(vif.addr, rt2x00dev->mac, 6);

    r = rt2x00mac_add_interface(&hw, &vif);

    if (r < 0) {
        rt2x00_err(rt2x00dev, "Failed to add vif... %s\n", strerror(errno));
        libusb_close(rt2x00dev->dev);
        rt2x00usb_free(rt2x00dev);
        free(*udev);
        return r;
    } else {
        rt2x00_info(rt2x00dev, "We think we added a vif...!\n");
    }

    /*
    rt2800usb_userspace_set_channel(*udev, 1, NL80211_CHAN_WIDTH_20_NOHT);
    */

    return 0;
}


int rt2800usb_probe_device(struct libusb_device_descriptor *desc, 
        struct userspace_wifi_probe_dev **probe_dev) {
    unsigned int x;

    for (x = 0; x < sizeof(rt2800usb_device_table) / sizeof(struct usb_device_id); x++) {
        if (rt2800usb_device_table[x].match_flags != USB_DEVICE_ID_MATCH_DEVICE)
            continue;

        if (rt2800usb_device_table[x].idVendor == desc->idVendor &&
                rt2800usb_device_table[x].idProduct == desc->idProduct) {
            *probe_dev = (struct userspace_wifi_probe_dev *) malloc(sizeof(struct userspace_wifi_probe_dev));

            (*probe_dev)->device_id_match = &(rt2800usb_device_table[x]);

            (*probe_dev)->driver_name = strdup("rt2800usb");
            (*probe_dev)->device_type = strdup("rt2800usb");

            (*probe_dev)->open_device = &rt2800usb_open_device;

            return 1;
        }

    }

    return 0;
}


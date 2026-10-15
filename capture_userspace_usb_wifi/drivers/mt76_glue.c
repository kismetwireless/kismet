/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* Functions the vendored mt76 USB code references from mt76 files that aren't vendored
 * (MMIO DMA, PCI and debugfs).  Kept outside drivers/mt76 so that directory stays an
 * unmodified copy of the kernel. */

#include "mt76/mt76.h"
#include "mt76/mt792x.h"
#include "mt76/mt7921/mt7921.h"

/* From mt7925/mt7925.h and mt76x02.h, which can't be included alongside mt7921.h */
int mt7925_init_debugfs(struct mt792x_dev *dev);
struct mt76x02_dev;
void mt76x02_wdt_work(struct work_struct *work);
void mt76x02_init_debugfs(struct mt76x02_dev *dev);

/* From mt76 dma.c (BSD-3-Clause-Clear) */
void
mt76_put_txwi(struct mt76_dev *dev, struct mt76_txwi_cache *t)
{
	if (!t)
		return;

	spin_lock(&dev->lock);
	list_add(&t->list, &dev->txwi_cache);
	spin_unlock(&dev->lock);
}

/* From mt76 mmio.c; USB devices have no interrupt mask register */
void mt76_set_irq_mask(struct mt76_dev *dev, u32 addr, u32 clear, u32 set) {
    (void) dev; (void) addr; (void) clear; (void) set;
}

/* From mt76x02_mmio.c; the watchdog is only scheduled by MMIO devices */
void mt76x02_wdt_work(struct work_struct *work) {
    (void) work;
}

/* PCI only; USB devices never need a WPDMA reinit */
int mt792x_wpdma_reinit_cond(struct mt792x_dev *dev) {
    (void) dev;
    return 0;
}

/* No debugfs */
int mt7921_init_debugfs(struct mt792x_dev *dev) {
    (void) dev;
    return 0;
}

int mt7925_init_debugfs(struct mt792x_dev *dev) {
    (void) dev;
    return 0;
}

void mt76x02_init_debugfs(struct mt76x02_dev *dev) {
    (void) dev;
}

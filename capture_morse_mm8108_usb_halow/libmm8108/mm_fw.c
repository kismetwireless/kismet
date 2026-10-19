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

/* Firmware and board config loading, and chip boot, from morse_driver firmware.c.
 *
 * Firmware and BCF files are 32-bit little-endian ELF.  Firmware segments are written to
 * chip memory; the BCF board config and regulatory sections are written to the address
 * the firmware declares in its .fw_info section.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "mm8108.h"
#include "mm_util.h"

#define MM_FW_MAX_FILE_SIZE     (4 * 1024 * 1024)
#define MM_BCF_DEFAULT_SIZE     2048
#define MM_BCF_MAX_SIZE         (64 * 1024)
#define MM_EXT_HOST_TABLE_MAX   4096
#define MM_BOOT_TRIES           3
#define MM_BOOT_TIMEOUT_MS      550
#define MM_TRIGGER_DELAY_MS     60

#define ELF_EHDR_LEN            52
#define ELF_PHDR_LEN            32
#define ELF_SHDR_LEN            40
#define ELF_PT_LOAD             1

/* Flash regions are only used by self-hosted builds */
#define MM_IFLASH_BASE          0x400000
#define MM_DFLASH_BASE          0xC00000

#define FW_INFO_TLV_BCF_ADDR    1
#define FW_INFO_TLV_BCF_SIZE    3

#define EXT_TAG_INSERT_SKB_CHECKSUM 2
#define EXT_TAG_YAPS_TABLE      3

struct mm_file {
    uint8_t *data;
    size_t len;
};

struct mm_elf {
    const struct mm_file *file;
    uint32_t entry;
    uint32_t phoff;
    uint16_t phentsize;
    uint16_t phnum;
    uint32_t shoff;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
    /* Section name string table */
    uint32_t strtab_off;
    uint32_t strtab_len;
};

struct mm_elf_shdr {
    uint32_t name;
    uint32_t addr;
    uint32_t offset;
    uint32_t size;
};

static int mm_file_load(struct mm8108_dev *dev, const char *path, struct mm_file *file) {
    FILE *f;
    long sz;

    file->data = NULL;
    file->len = 0;

    if ((f = fopen(path, "rb")) == NULL)
        return mm_error(dev, -errno, "could not open %s: %s", path, strerror(errno));

    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return mm_error(dev, -EIO, "could not size %s", path);
    }

    if (sz == 0 || sz > MM_FW_MAX_FILE_SIZE) {
        fclose(f);
        return mm_error(dev, -EFBIG, "%s has an invalid size (%ld)", path, sz);
    }

    if ((file->data = malloc((size_t) sz)) == NULL) {
        fclose(f);
        return mm_error(dev, -ENOMEM, "could not allocate %ld bytes for %s", sz, path);
    }

    if (fread(file->data, 1, (size_t) sz, f) != (size_t) sz) {
        fclose(f);
        free(file->data);
        file->data = NULL;
        return mm_error(dev, -EIO, "could not read %s", path);
    }

    fclose(f);
    file->len = (size_t) sz;

    return 0;
}

static void mm_file_free(struct mm_file *file) {
    free(file->data);
    file->data = NULL;
    file->len = 0;
}

static bool mm_range_ok(const struct mm_file *file, uint64_t off, uint64_t len) {
    return off <= file->len && len <= file->len - off;
}

static int mm_elf_section(const struct mm_elf *elf, unsigned int i, struct mm_elf_shdr *shdr) {
    const uint64_t off = (uint64_t) elf->shoff + (uint64_t) i * elf->shentsize;
    const uint8_t *p;

    if (i >= elf->shnum || !mm_range_ok(elf->file, off, ELF_SHDR_LEN))
        return -EINVAL;

    p = elf->file->data + off;
    shdr->name = mm_get_le32(p);
    shdr->addr = mm_get_le32(p + 12);
    shdr->offset = mm_get_le32(p + 16);
    shdr->size = mm_get_le32(p + 20);

    return 0;
}

/* Section name, or NULL if it isn't a terminated string inside the string table */
static const char *mm_elf_section_name(const struct mm_elf *elf, const struct mm_elf_shdr *shdr) {
    const char *s;

    if (shdr->name >= elf->strtab_len)
        return NULL;

    s = (const char *) elf->file->data + elf->strtab_off + shdr->name;

    if (memchr(s, 0, elf->strtab_len - shdr->name) == NULL)
        return NULL;

    return s;
}

static int mm_elf_parse(struct mm8108_dev *dev, const struct mm_file *file, struct mm_elf *elf,
        const char *what) {
    const uint8_t *p = file->data;
    struct mm_elf_shdr strtab;

    memset(elf, 0, sizeof(*elf));
    elf->file = file;

    if (file->len < ELF_EHDR_LEN || memcmp(p, "\x7f" "ELF", 4) != 0)
        return mm_error(dev, -EINVAL, "%s is not an ELF file", what);

    /* 32 bit, little endian */
    if (p[4] != 1 || p[5] != 1)
        return mm_error(dev, -EINVAL, "%s is not a 32-bit little-endian ELF file", what);

    elf->entry = mm_get_le32(p + 24);
    elf->phoff = mm_get_le32(p + 28);
    elf->shoff = mm_get_le32(p + 32);
    elf->phentsize = mm_get_le16(p + 42);
    elf->phnum = mm_get_le16(p + 44);
    elf->shentsize = mm_get_le16(p + 46);
    elf->shnum = mm_get_le16(p + 48);
    elf->shstrndx = mm_get_le16(p + 50);

    if ((elf->phnum != 0 && elf->phentsize < ELF_PHDR_LEN) ||
            (elf->shnum != 0 && elf->shentsize < ELF_SHDR_LEN))
        return mm_error(dev, -EINVAL, "%s has invalid ELF header sizes", what);

    if (mm_elf_section(elf, elf->shstrndx, &strtab) < 0 ||
            !mm_range_ok(file, strtab.offset, strtab.size))
        return mm_error(dev, -EINVAL, "%s has no valid section string table", what);

    elf->strtab_off = strtab.offset;
    elf->strtab_len = strtab.size;

    return 0;
}

static int mm_elf_find_section(const struct mm_elf *elf, const char *name,
        struct mm_elf_shdr *shdr) {
    for (unsigned int i = 0; i < elf->shnum; i++) {
        const char *sn;

        if (mm_elf_section(elf, i, shdr) < 0)
            continue;

        if ((sn = mm_elf_section_name(elf, shdr)) != NULL && strcmp(sn, name) == 0)
            return mm_range_ok(elf->file, shdr->offset, shdr->size) ? 0 : -EINVAL;
    }

    return -ENOENT;
}

/* .fw_info is a list of {le16 type, le16 len, value[len]} */
static int mm_fw_parse_info(struct mm8108_dev *dev, const struct mm_elf *elf) {
    struct mm_elf_shdr shdr;
    const uint8_t *p, *end;

    dev->bcf_addr = 0;
    dev->bcf_size = MM_BCF_DEFAULT_SIZE;

    if (mm_elf_find_section(elf, ".fw_info", &shdr) < 0)
        return mm_error(dev, -EINVAL, "firmware has no .fw_info section");

    p = elf->file->data + shdr.offset;
    end = p + shdr.size;

    while (end - p >= 4) {
        const uint16_t type = mm_get_le16(p);
        const uint16_t len = mm_get_le16(p + 2);

        if (len > end - p - 4)
            break;

        if (type == FW_INFO_TLV_BCF_ADDR && len == 4)
            dev->bcf_addr = mm_get_le32(p + 4);
        else if (type == FW_INFO_TLV_BCF_SIZE && len == 4 && mm_get_le32(p + 4) != 0)
            dev->bcf_size = mm_get_le32(p + 4);

        p += 4 + len;
    }

    if (dev->bcf_addr == 0)
        return mm_error(dev, -EINVAL, "firmware does not declare a BCF address");

    if (dev->bcf_size > MM_BCF_MAX_SIZE)
        return mm_error(dev, -EINVAL, "firmware declares an invalid BCF size %u", dev->bcf_size);

    mm_log(dev, 2, "BCF address 0x%08x, max size %u", dev->bcf_addr, dev->bcf_size);

    return 0;
}

/* Writes data padded to a word with 0xFF, as the driver does */
static int mm_write_padded(struct mm8108_dev *dev, uint32_t addr, const uint8_t *data, size_t len) {
    const size_t padded = MM_ROUND_UP4(len);
    uint8_t *buf;
    int r;

    if ((buf = malloc(padded)) == NULL)
        return -ENOMEM;

    memcpy(buf, data, len);
    memset(buf + len, 0xFF, padded - len);

    r = mm_dm_write(dev, addr, buf, padded);
    free(buf);

    return r;
}

static int mm_fw_load(struct mm8108_dev *dev, const struct mm_elf *elf) {
    struct mm_elf_shdr shdr;
    int r;

    for (unsigned int i = 0; i < elf->phnum; i++) {
        const uint64_t off = (uint64_t) elf->phoff + (uint64_t) i * elf->phentsize;
        const uint8_t *p;

        if (!mm_range_ok(elf->file, off, ELF_PHDR_LEN))
            return mm_error(dev, -EINVAL, "firmware program header %u is out of range", i);

        p = elf->file->data + off;

        const uint32_t type = mm_get_le32(p);
        const uint32_t offset = mm_get_le32(p + 4);
        const uint32_t paddr = mm_get_le32(p + 12);
        const uint32_t filesz = mm_get_le32(p + 16);
        const uint32_t memsz = mm_get_le32(p + 20);

        if (paddr == MM_IFLASH_BASE || paddr == MM_DFLASH_BASE)
            continue;

        if (type != ELF_PT_LOAD || memsz == 0 || filesz == 0 || offset == 0)
            continue;

        if (!mm_range_ok(elf->file, offset, filesz))
            return mm_error(dev, -EINVAL, "firmware segment %u is out of range", i);

        mm_log(dev, 3, "loading %u bytes at 0x%08x", filesz, paddr);

        if ((r = mm_write_padded(dev, paddr, elf->file->data + offset, filesz)) < 0)
            return mm_error(dev, r, "could not write firmware segment to 0x%08x", paddr);
    }

    if (mm_elf_find_section(elf, ".security_manifest", &shdr) == 0)
        if ((r = mm_reg32_write(dev, MM8108_REG_SECURITY_MANIFEST_PTR, shdr.addr)) < 0)
            return mm_error(dev, r, "could not set the security manifest pointer");

    if (elf->entry != 0 && !mm_mem_restricted(dev))
        if ((r = mm_reg32_write(dev, MM8108_REG_APPS_BOOT_ADDR, elf->entry)) < 0)
            return mm_error(dev, r, "could not set the boot address");

    return 0;
}

static const char *mm_bcf_country_fallback(const char *country) {
    static const char *table[][2] = {
        { "MX", "US" },
        { "AR", "AU" },
        { "CL", "AU" },
        { "CO", "AU" },
    };

    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++)
        if (strncmp(country, table[i][0], 2) == 0)
            return table[i][1];

    return NULL;
}

static int mm_bcf_find_regdom(const struct mm_elf *elf, const char *country,
        struct mm_elf_shdr *shdr) {
    char name[16];

    snprintf(name, sizeof(name), ".regdom_%.2s", country);
    return mm_elf_find_section(elf, name, shdr);
}

/* Board configs list the chip families they support in .chips */
#define MM_BCF_CHIP_FAMILY      "mm810x"
#define MM_BCF_REFERENCE        "bcf_mf15457.bin"
#define MM_BCF_REFERENCE_LINUX  "bcf_mm8108_mf15457.bin"

size_t mm_bcf_default_names(const struct mm8108_dev *dev,
        char names[MM_BCF_MAX_NAMES][MM_BCF_NAME_LEN]) {
    size_t n = 0;

    if (dev->board_type != 0)
        snprintf(names[n++], MM_BCF_NAME_LEN, "bcf_boardtype_%04x.bin", dev->board_type);

    snprintf(names[n++], MM_BCF_NAME_LEN, "bcf_default.bin");
    snprintf(names[n++], MM_BCF_NAME_LEN, "%s", MM_BCF_REFERENCE);
    snprintf(names[n++], MM_BCF_NAME_LEN, "%s", MM_BCF_REFERENCE_LINUX);

    return n;
}

/* Copies printable ascii from a section, stopping at a NUL; -ENOENT if there's no such
 * section, -EINVAL if it holds anything else */
static int mm_bcf_section_string(const struct mm_elf *elf, const char *name, char *out,
        size_t out_len) {
    struct mm_elf_shdr shdr;
    size_t n = 0;
    int r;

    out[0] = 0;

    if ((r = mm_elf_find_section(elf, name, &shdr)) < 0)
        return r;

    for (uint32_t i = 0; i < shdr.size; i++) {
        const char c = (char) elf->file->data[shdr.offset + i];

        if (c == 0)
            break;

        if (c < 0x20 || c > 0x7E) {
            out[0] = 0;
            return -EINVAL;
        }

        if (n + 1 < out_len)
            out[n++] = c;
    }

    out[n] = 0;
    return 0;
}

/* The board description is JSON naming the module, or in older files the bare name */
static void mm_bcf_module_name(const struct mm_elf *elf, char *out, size_t out_len) {
    char desc[512];
    const char *p;
    size_t n = 0;

    out[0] = 0;

    if (mm_bcf_section_string(elf, ".board_desc", desc, sizeof(desc)) < 0 || desc[0] == 0)
        return;

    if (desc[0] != '{') {
        snprintf(out, out_len, "%s", desc);
        return;
    }

    if ((p = strstr(desc, "\"module\"")) == NULL)
        return;

    p += strlen("\"module\"");
    while (*p == ' ' || *p == ':')
        p++;

    if (*p++ != '"')
        return;

    while (*p != 0 && *p != '"' && *p != '\\' && n + 1 < out_len)
        out[n++] = *p++;

    out[n] = 0;
}

/* A board config for another chip family would program the wrong radio settings */
static int mm_bcf_check(struct mm8108_dev *dev, const struct mm_elf *elf) {
    char chips[64];
    int r;

    /* Older board configs have no chip list */
    if ((r = mm_bcf_section_string(elf, ".chips", chips, sizeof(chips))) == -EINVAL ||
            (r == 0 && chips[0] == 0))
        return mm_error(dev, -EINVAL, "board config has an invalid chip list");

    if (r == 0 && strcasecmp(chips, MM_BCF_CHIP_FAMILY) != 0)
        return mm_error(dev, -EINVAL, "board config is for %s chips, not MM8108", chips);

    mm_bcf_module_name(elf, dev->bcf_module, sizeof(dev->bcf_module));

    if (dev->bcf_module[0] != 0)
        mm_log(dev, 1, "board config for module %s", dev->bcf_module);

    return 0;
}

/* The board config is followed by the regulatory section for the country */
static int mm_bcf_load(struct mm8108_dev *dev, const struct mm_elf *elf, const char *country) {
    struct mm_elf_shdr board, regdom;
    uint8_t *buf;
    size_t board_len, regdom_len;
    int r;

    if (mm_elf_find_section(elf, ".board_config", &board) < 0)
        return mm_error(dev, -EINVAL, "BCF has no .board_config section");

    if (mm_bcf_find_regdom(elf, country, &regdom) < 0) {
        const char *fallback = mm_bcf_country_fallback(country);

        if (fallback == NULL || mm_bcf_find_regdom(elf, fallback, &regdom) < 0)
            return mm_error(dev, -ENOENT, "BCF has no regulatory section for %s", country);

        mm_log(dev, 1, "using the %s regulatory section for %s", fallback, country);
    }

    board_len = MM_ROUND_UP4(board.size);
    regdom_len = MM_ROUND_UP4(regdom.size);

    if (board_len + regdom_len > dev->bcf_size)
        return mm_error(dev, -EOVERFLOW, "BCF sections (%zu bytes) exceed the firmware limit (%u)",
                board_len + regdom_len, dev->bcf_size);

    if ((buf = malloc(board_len + regdom_len)) == NULL)
        return -ENOMEM;

    memset(buf, 0xFF, board_len + regdom_len);
    memcpy(buf, elf->file->data + board.offset, board.size);
    memcpy(buf + board_len, elf->file->data + regdom.offset, regdom.size);

    r = mm_dm_write(dev, dev->bcf_addr, buf, board_len + regdom_len);
    free(buf);

    if (r < 0)
        return mm_error(dev, r, "could not write the BCF");

    mm_log(dev, 2, "loaded BCF board config (%u bytes) and %.2s regulatory section (%u bytes)",
            board.size, country, regdom.size);

    return 0;
}

static int mm_fw_trigger(struct mm8108_dev *dev) {
    int r;

    /* Clear latched AON state, keeping the USB power domain on */
    if (!mm_mem_restricted(dev)) {
        if ((r = mm_reg32_write(dev, MM8108_REG_AON, MM8108_REG_AON_RESET_USB_VALUE)) < 0)
            return r;
        for (unsigned int i = 1; i < MM8108_REG_AON_COUNT; i++)
            if ((r = mm_reg32_write(dev, MM8108_REG_AON + i * 4, 0)) < 0)
                return r;
        if ((r = mm_toggle_aon_latch(dev)) < 0)
            return r;
    }

    if ((r = mm_reg32_write(dev, MM8108_REG_MSI, 1)) < 0)
        return r;

    mm_mem_access_reset_cache(dev);
    mm_sleep_us(MM_TRIGGER_DELAY_MS * 1000);

    return 0;
}

static int mm_wait_host_table(struct mm8108_dev *dev) {
    const uint64_t start = mm_monotonic_ms();
    int r;

    dev->host_table_ptr = 0;

    while (1) {
        if ((r = mm_reg32_read(dev, MM8108_REG_MANIFEST_PTR, &dev->host_table_ptr)) < 0)
            return r;

        if (dev->host_table_ptr != 0)
            break;

        if (mm_monotonic_ms() - start > MM_BOOT_TIMEOUT_MS)
            return -ETIMEDOUT;

        mm_sleep_us(5000);
    }

    mm_log(dev, 1, "firmware booted in %llu ms", (unsigned long long) (mm_monotonic_ms() - start));

    return 0;
}

static int mm_boot_try(struct mm8108_dev *dev, const struct mm_elf *fw, const struct mm_elf *bcf,
        const char *country) {
    uint32_t magic;
    int r;

    if ((r = mm_digital_reset(dev)) < 0)
        return r;

    if ((r = mm_reg32_write(dev, MM8108_REG_MANIFEST_PTR, 0)) < 0)
        return mm_error(dev, r, "could not clear the manifest pointer");

    if ((r = mm_fw_load(dev, fw)) < 0)
        return r;

    /* Without a BCF the firmware boots in failsafe mode */
    if (bcf != NULL && mm_bcf_load(dev, bcf, country) < 0)
        mm_log(dev, 1, "BCF load failed, firmware will start in failsafe mode");

    if ((r = mm_fw_trigger(dev)) < 0)
        return mm_error(dev, r, "could not start the firmware");

    if (dev->chip_id == MM8108_CHIP_ID_B3) {
        uint32_t sb;

        if ((r = mm_reg32_read(dev, MM8108_REG_SECURE_BOOT_STATUS, &sb)) < 0)
            return r;

        if ((sb & 0xFF) != 0)
            return mm_error(dev, -EIO, "firmware secure boot failed (0x%x)", sb & 0xFF);
    }

    if ((r = mm_wait_host_table(dev)) < 0)
        return mm_error(dev, r, "firmware did not start");

    if ((r = mm_reg32_read(dev, dev->host_table_ptr, &magic)) < 0)
        return r;

    if (magic != MM8108_HOST_MAGIC)
        return mm_error(dev, -EIO, "firmware magic mismatch (0x%08x)", magic);

    return 0;
}

/* Extended host table: le32 length, MAC[6], then {le16 tag, le16 len incl header} TLVs */
static int mm_parse_ext_host_table(struct mm8108_dev *dev) {
    uint32_t addr, len;
    uint8_t *buf;
    size_t off;
    int r;

    if ((r = mm_reg32_read(dev, dev->host_table_ptr + 24, &addr)) < 0)
        return r;

    if (addr == 0)
        return mm_error(dev, -EINVAL, "firmware has no extended host table");

    if ((r = mm_reg32_read(dev, addr, &len)) < 0)
        return r;

    if (len < 10 || len > MM_EXT_HOST_TABLE_MAX)
        return mm_error(dev, -EINVAL, "invalid extended host table length %u", len);

    if ((buf = malloc(MM_ROUND_UP4(len))) == NULL)
        return -ENOMEM;

    if ((r = mm_dm_read(dev, addr, buf, MM_ROUND_UP4(len))) < 0) {
        free(buf);
        return r;
    }

    memcpy(dev->mac, buf + 4, 6);
    dev->validate_checksum = false;
    dev->yaps.valid = false;

    off = 10;
    while (off + 4 <= len) {
        const uint16_t tag = mm_get_le16(buf + off);
        const uint16_t tlen = mm_get_le16(buf + off + 2);

        if (tlen < 4 || tlen > len - off)
            break;

        if (tag == EXT_TAG_INSERT_SKB_CHECKSUM && tlen >= 5) {
            dev->validate_checksum = buf[off + 4] != 0;
        } else if (tag == EXT_TAG_YAPS_TABLE) {
            if ((r = mm_yaps_parse_table(dev, buf + off + 4, tlen - 4)) < 0) {
                free(buf);
                return r;
            }
        }

        off += tlen;
    }

    free(buf);

    if (!dev->yaps.valid)
        return mm_error(dev, -EINVAL, "firmware did not provide a YAPS table");

    mm_log(dev, 1, "device MAC %02x:%02x:%02x:%02x:%02x:%02x, checksums %s",
            dev->mac[0], dev->mac[1], dev->mac[2], dev->mac[3], dev->mac[4], dev->mac[5],
            dev->validate_checksum ? "on" : "off");

    return 0;
}

int mm_boot(struct mm8108_dev *dev, const struct mm8108_boot_config *cfg) {
    struct mm_file fw_file = { 0 }, bcf_file = { 0 };
    struct mm_elf fw_elf, bcf_elf;
    bool have_bcf = false;
    int r, tries;

    dev->bcf_module[0] = 0;

    if ((r = mm_file_load(dev, cfg->firmware_path, &fw_file)) < 0)
        return r;

    if ((r = mm_elf_parse(dev, &fw_file, &fw_elf, "firmware")) < 0 ||
            (r = mm_fw_parse_info(dev, &fw_elf)) < 0)
        goto out;

    if (cfg->bcf_path != NULL) {
        if ((r = mm_file_load(dev, cfg->bcf_path, &bcf_file)) < 0 ||
                (r = mm_elf_parse(dev, &bcf_file, &bcf_elf, "BCF")) < 0 ||
                (r = mm_bcf_check(dev, &bcf_elf)) < 0)
            goto out;
        have_bcf = true;
    } else {
        mm_log(dev, 1, "no BCF, firmware will start in failsafe mode");
    }

    for (tries = 0; tries < MM_BOOT_TRIES; tries++) {
        if ((r = mm_boot_try(dev, &fw_elf, have_bcf ? &bcf_elf : NULL, cfg->country)) == 0)
            break;
        mm_log(dev, 1, "boot attempt %d failed: %s", tries + 1, dev->errstr);
    }

    if (r < 0)
        goto out;

    /* Restriction state is fixed while firmware runs */
    mm_mem_restricted(dev);
    dev->hw_on = true;

    if ((r = mm_reg32_read(dev, dev->host_table_ptr + 4, &dev->fw_version)) < 0 ||
            (r = mm_reg32_read(dev, dev->host_table_ptr + 12, &dev->fw_flags)) < 0)
        goto out;

    const uint32_t major = (dev->fw_version >> 22) & 0x3FF;
    const uint32_t minor = (dev->fw_version >> 10) & 0xFFF;
    const uint32_t patch = dev->fw_version & 0x3FF;

    mm_log(dev, 1, "firmware interface version %u.%u.%u, flags 0x%08x", major, minor, patch,
            dev->fw_flags);

    if (major != MM8108_FW_SEMVER_MAJOR) {
        r = mm_error(dev, -EPROTO, "incompatible firmware interface version %u.%u.%u (need %u.x)",
                major, minor, patch, MM8108_FW_SEMVER_MAJOR);
        goto out;
    }

    if (minor != MM8108_FW_SEMVER_MINOR)
        mm_log(dev, 1, "firmware interface minor version %u differs from %u", minor,
                MM8108_FW_SEMVER_MINOR);

    if (dev->fw_flags & MM8108_FW_FLAG_FAILSAFE)
        mm_log(dev, 0, "warning: firmware is running in failsafe mode (bad or missing BCF)");

    if ((r = mm_parse_ext_host_table(dev)) < 0)
        goto out;

    if ((r = mm_irq_enable(dev, MM8108_INT_YAPS_PKT_WAITING | MM8108_INT_YAPS_PKT_FREED)) < 0)
        goto out;

    /* Anything already raised is picked up by the first service */
    dev->rx_more = true;
    r = mm_usb_int_start(dev);

out:
    mm_file_free(&fw_file);
    mm_file_free(&bcf_file);
    return r;
}

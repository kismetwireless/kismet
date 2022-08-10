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

#ifndef __RT2x00USB_H__
#define __RT2x00USB_H__ 

#include "kernel/types.h"

#include "rt2800usb/rt2x00.h"

/**
 * enum rt2x00usb_vendor_request: USB vendor commands.
 */
enum rt2x00usb_vendor_request {
    USB_DEVICE_MODE = 1,
    USB_SINGLE_WRITE = 2,
    USB_SINGLE_READ = 3,
    USB_MULTI_WRITE = 6,
    USB_MULTI_READ = 7,
    USB_EEPROM_WRITE = 8,
    USB_EEPROM_READ = 9,
    USB_LED_CONTROL = 10, /* RT73USB */
    USB_RX_CONTROL = 12,
};

/**
 * enum rt2x00usb_mode_offset: Device modes offset.
 */
enum rt2x00usb_mode_offset {
    USB_MODE_RESET = 1,
    USB_MODE_UNPLUG = 2,
    USB_MODE_FUNCTION = 3,
    USB_MODE_TEST = 4,
    USB_MODE_SLEEP = 7,	/* RT73USB */
    USB_MODE_FIRMWARE = 8,	/* RT73USB */
    USB_MODE_WAKEUP = 9,	/* RT73USB */
    USB_MODE_AUTORUN = 17, /* RT2800USB */
};

/**
 * rt2x00usb_vendor_request - Send register command to device
 * @rt2x00dev: Pointer to &struct rt2x00_dev
 * @request: USB vendor command (See &enum rt2x00usb_vendor_request)
 * @requesttype: Request type &USB_VENDOR_REQUEST_*
 * @offset: Register offset to perform action on
 * @value: Value to write to device
 * @buffer: Buffer where information will be read/written to by device
 * @buffer_length: Size of &buffer
 * @timeout: Operation timeout
 *
 * This is the main function to communicate with the device,
 * the &buffer argument _must_ either be NULL or point to
 * a buffer allocated by malloc. Failure to do so can lead
 * to unexpected behavior depending on the architecture.
 */
int rt2x00usb_vendor_request(struct rt2x00_dev *rt2x00dev,
        const u8 request, const u8 requesttype,
        const u16 offset, const u16 value,
        void *buffer, const u16 buffer_length,
        const int timeout);

/**
 * rt2x00usb_vendor_request_buff - Send register command to device (buffered)
 * @rt2x00dev: Pointer to &struct rt2x00_dev
 * @request: USB vendor command (See &enum rt2x00usb_vendor_request)
 * @requesttype: Request type &USB_VENDOR_REQUEST_*
 * @offset: Register offset to perform action on
 * @buffer: Buffer where information will be read/written to by device
 * @buffer_length: Size of &buffer
 *
 * This function will use a previously with malloc allocated cache
 * to communicate with the device. The contents of the buffer pointer
 * will be copied to this cache when writing, or read from the cache
 * when reading.
 * Buffers send to &rt2x00usb_vendor_request _must_ be allocated with
 * kmalloc. Hence the reason for using a previously allocated cache
 * which has been allocated properly.
 */
int rt2x00usb_vendor_request_buff(struct rt2x00_dev *rt2x00dev,
        const u8 request, const u8 requesttype,
        const u16 offset, void *buffer,
        const u16 buffer_length);

/**
 * rt2x00usb_vendor_request_buff - Send register command to device (buffered)
 * @rt2x00dev: Pointer to &struct rt2x00_dev
 * @request: USB vendor command (See &enum rt2x00usb_vendor_request)
 * @requesttype: Request type &USB_VENDOR_REQUEST_*
 * @offset: Register offset to perform action on
 * @buffer: Buffer where information will be read/written to by device
 * @buffer_length: Size of &buffer
 * @timeout: Operation timeout
 *
 * A version of &rt2x00usb_vendor_request_buff which must be called
 * if the usb_cache_mutex is already held.
 */
int rt2x00usb_vendor_req_buff_lock(struct rt2x00_dev *rt2x00dev,
        const u8 request, const u8 requesttype,
        const u16 offset, void *buffer,
        const u16 buffer_length, const int timeout);

/**
 * rt2x00usb_vendor_request_sw - Send single register command to device
 * @rt2x00dev: Pointer to &struct rt2x00_dev
 * @request: USB vendor command (See &enum rt2x00usb_vendor_request)
 * @offset: Register offset to perform action on
 * @value: Value to write to device
 * @timeout: Operation timeout
 *
 * Simple wrapper around rt2x00usb_vendor_request to write a single
 * command to the device. Since we don't use the buffer argument we
 * don't have to worry about kmalloc here.
 */
static inline int rt2x00usb_vendor_request_sw(struct rt2x00_dev *rt2x00dev,
        const u8 request,
        const u16 offset,
        const u16 value,
        const int timeout) {
    return rt2x00usb_vendor_request(rt2x00dev, request,
            USB_VENDOR_REQUEST_OUT, offset,
            value, NULL, 0, timeout);
}

/**
 * rt2x00usb_eeprom_read - Read eeprom from device
 * @rt2x00dev: Pointer to &struct rt2x00_dev
 * @eeprom: Pointer to eeprom array to store the information in
 * @length: Number of bytes to read from the eeprom
 *
 * Simple wrapper around rt2x00usb_vendor_request to read the eeprom
 * from the device. Note that the eeprom argument _must_ be allocated using
 * kmalloc for correct handling inside the kernel USB layer.
 */
static inline int rt2x00usb_eeprom_read(struct rt2x00_dev *rt2x00dev,
        __le16 *eeprom, const u16 length) {
    return rt2x00usb_vendor_request(rt2x00dev, USB_EEPROM_READ,
            USB_VENDOR_REQUEST_IN, 0, 0,
            eeprom, length, EEPROM_TIMEOUT);
}

/**
 * rt2x00usb_register_read - Read 32bit register word
 * @rt2x00dev: Device pointer, see &struct rt2x00_dev.
 * @offset: Register offset
 *
 * This function is a simple wrapper for 32bit register access
 * through rt2x00usb_vendor_request_buff().
 */
static inline u32 rt2x00usb_register_read(struct rt2x00_dev *rt2x00dev,
        const unsigned int offset) {
    __le32 reg = 0;
    rt2x00usb_vendor_request_buff(rt2x00dev, USB_MULTI_READ,
            USB_VENDOR_REQUEST_IN, offset,
            &reg, sizeof(reg));
    return le32_to_cpu(reg);
}

/**
 * rt2x00usb_register_read_lock - Read 32bit register word
 * @rt2x00dev: Device pointer, see &struct rt2x00_dev.
 * @offset: Register offset
 *
 * This function is a simple wrapper for 32bit register access
 * through rt2x00usb_vendor_req_buff_lock().
 */
static inline u32 rt2x00usb_register_read_lock(struct rt2x00_dev *rt2x00dev,
        const unsigned int offset) {
    __le32 reg = 0;
    rt2x00usb_vendor_req_buff_lock(rt2x00dev, USB_MULTI_READ,
            USB_VENDOR_REQUEST_IN, offset,
            &reg, sizeof(reg), REGISTER_TIMEOUT);
    return le32_to_cpu(reg);
}

/**
 * rt2x00usb_register_multiread - Read 32bit register words
 * @rt2x00dev: Device pointer, see &struct rt2x00_dev.
 * @offset: Register offset
 * @value: Pointer to where register contents should be stored
 * @length: Length of the data
 *
 * This function is a simple wrapper for 32bit register access
 * through rt2x00usb_vendor_request_buff().
 */
static inline void rt2x00usb_register_multiread(struct rt2x00_dev *rt2x00dev,
        const unsigned int offset,
        void *value, const u32 length) {
    rt2x00usb_vendor_request_buff(rt2x00dev, USB_MULTI_READ,
            USB_VENDOR_REQUEST_IN, offset,
            value, length);
}

/**
 * rt2x00usb_register_write - Write 32bit register word
 * @rt2x00dev: Device pointer, see &struct rt2x00_dev.
 * @offset: Register offset
 * @value: Data which should be written
 *
 * This function is a simple wrapper for 32bit register access
 * through rt2x00usb_vendor_request_buff().
 */
static inline void rt2x00usb_register_write(struct rt2x00_dev *rt2x00dev,
        const unsigned int offset,
        u32 value) {
    __le32 reg = cpu_to_le32(value);
    rt2x00usb_vendor_request_buff(rt2x00dev, USB_MULTI_WRITE,
            USB_VENDOR_REQUEST_OUT, offset,
            &reg, sizeof(reg));
}

/**
 * rt2x00usb_register_write_lock - Write 32bit register word
 * @rt2x00dev: Device pointer, see &struct rt2x00_dev.
 * @offset: Register offset
 * @value: Data which should be written
 *
 * This function is a simple wrapper for 32bit register access
 * through rt2x00usb_vendor_req_buff_lock().
 */
static inline void rt2x00usb_register_write_lock(struct rt2x00_dev *rt2x00dev,
        const unsigned int offset,
        u32 value) {
    __le32 reg = cpu_to_le32(value);
    rt2x00usb_vendor_req_buff_lock(rt2x00dev, USB_MULTI_WRITE,
            USB_VENDOR_REQUEST_OUT, offset,
            &reg, sizeof(reg), REGISTER_TIMEOUT);
}

/**
 * rt2x00usb_register_multiwrite - Write 32bit register words
 * @rt2x00dev: Device pointer, see &struct rt2x00_dev.
 * @offset: Register offset
 * @value: Data which should be written
 * @length: Length of the data
 *
 * This function is a simple wrapper for 32bit register access
 * through rt2x00usb_vendor_request_buff().
 */
static inline void rt2x00usb_register_multiwrite(struct rt2x00_dev *rt2x00dev,
        const unsigned int offset,
        const void *value,
        const u32 length) {
    rt2x00usb_vendor_request_buff(rt2x00dev, USB_MULTI_WRITE,
            USB_VENDOR_REQUEST_OUT, offset,
            (void *)value, length);
}

/**
 * rt2x00usb_regbusy_read - Read from register with busy check
 * @rt2x00dev: Device pointer, see &struct rt2x00_dev.
 * @offset: Register offset
 * @field: Field to check if register is busy
 * @reg: Pointer to where register contents should be stored
 *
 * This function will read the given register, and checks if the
 * register is busy. If it is, it will sleep for a couple of
 * microseconds before reading the register again. If the register
 * is not read after a certain timeout, this function will return
 * FALSE.
 */
int rt2x00usb_regbusy_read(struct rt2x00_dev *rt2x00dev,
        const unsigned int offset,
        const struct rt2x00_field32 field,
        u32 *reg);

/**
 * rt2x00usb_register_read_async - Asynchronously read 32bit register word
 * @rt2x00dev: Device pointer, see &struct rt2x00_dev.
 * @offset: Register offset
 * @callback: Functon to call when read completes.
 *
 * Submit a control URB to read a 32bit register. This safe to
 * be called from atomic context.  The callback will be called
 * when the URB completes. Otherwise the function is similar
 * to rt2x00usb_register_read().
 * When the callback function returns false, the memory will be cleaned up,
 * when it returns true, the urb will be fired again.
 */
void rt2x00usb_register_read_async(struct rt2x00_dev *rt2x00dev,
        const unsigned int offset,
        bool (*callback)(struct rt2x00_dev*, int, u32));

int rt2x00usb_alloc_reg(struct rt2x00_dev *rt2x00dev);
void rt2x00usb_free(struct rt2x00_dev *rt2x00dev);

int rt2x00usb_initialize(struct rt2x00_dev *rt2x00dev);

#endif /* ifndef RT2x00USB_H */

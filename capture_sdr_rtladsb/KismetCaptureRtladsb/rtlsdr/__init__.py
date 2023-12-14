import ctypes

__version__ = "2023.12.01"

class RadioMissingLibrtlsdr(Exception):
    pass

class RadioOpenError(Exception):
    pass

class RadioConfigError(RadioOpenError):
    pass

class RadioOperationalError(Exception):
    pass

class RtlSdr(object):
    def __init__(self):
        try:
            found_lib = False

            try:
                self.rtllib = ctypes.CDLL("librtlsdr.so.0")
                found_lib = True
            except OSError:
                pass

            try:
                if not found_lib:
                    self.rtllib = ctypes.CDLL("librtlsdr.so.2")
                    found_lib = True
            except OSError:
                pass

            try:
                if not found_lib:
                    self.rtllib = ctypes.CDLL("librtlsdr.dylib")
                    found_lib = True
            except OSError:
                pass

            try:
                if not found_lib:
                    self.rtllib = ctypes.CDLL("librtlsdr.dll")
                    found_lib = True
            except OSError:
                pass

            if not found_lib:
                raise OSError("could not find librtlsdr")

            self.rtl_get_device_count = self.rtllib.rtlsdr_get_device_count

            self.rtl_get_device_name = self.rtllib.rtlsdr_get_device_name
            self.rtl_get_device_name.argtypes = [ctypes.c_int]
            self.rtl_get_device_name.restype = ctypes.c_char_p

            self.rtl_get_usb_strings = self.rtllib.rtlsdr_get_device_usb_strings
            self.rtl_get_usb_strings.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

            self.rtl_get_index_by_serial = self.rtllib.rtlsdr_get_index_by_serial
            self.rtl_get_index_by_serial.argtypes = [ctypes.c_char_p]
            self.rtl_get_index_by_serial.restype = ctypes.c_int

            self.rtl_open = self.rtllib.rtlsdr_open
            self.rtl_open.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint]
            self.rtl_open.restype = ctypes.c_int

            self.rtl_set_tuner_gain_mode = self.rtllib.rtlsdr_set_tuner_gain_mode
            self.rtl_set_tuner_gain_mode.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.rtl_set_tuner_gain_mode.restype = ctypes.c_int

            self.rtl_set_tuner_gain = self.rtllib.rtlsdr_set_tuner_gain
            self.rtl_set_tuner_gain.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.rtl_set_tuner_gain.restype = ctypes.c_int

            self.rtl_set_agc_mode = self.rtllib.rtlsdr_set_agc_mode
            self.rtl_set_agc_mode.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.rtl_set_agc_mode.restype = ctypes.c_int

            self.rtl_set_freq_correction = self.rtllib.rtlsdr_set_freq_correction
            self.rtl_set_freq_correction.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.rtl_set_freq_correction.restype = ctypes.c_int

            self.rtl_set_center_freq = self.rtllib.rtlsdr_set_center_freq
            self.rtl_set_center_freq.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            self.rtl_set_center_freq.restype = ctypes.c_int

            self.rtl_get_center_freq = self.rtllib.rtlsdr_get_center_freq
            self.rtl_get_center_freq.argtypes = [ctypes.c_void_p]
            self.rtl_get_center_freq.restype = ctypes.c_int

            self.rtl_set_sample_rate = self.rtllib.rtlsdr_set_sample_rate
            self.rtl_set_sample_rate.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.rtl_set_sample_rate.restype = ctypes.c_int

            self.rtl_reset_buffer = self.rtllib.rtlsdr_reset_buffer
            self.rtl_reset_buffer.argtypes = [ctypes.c_void_p]
            self.rtl_reset_buffer.restype = ctypes.c_int

            self.rtl_read_async_cb_t = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, ctypes.c_void_p)
            # self.rtl_read_async_cb = self.rtl_read_async_cb_t(self.rtl_data_cb)

            self.rtl_read_async = self.rtllib.rtlsdr_read_async
            self.rtl_read_async.argtypes = [ctypes.c_void_p, self.rtl_read_async_cb_t, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]
            self.rtl_read_async.restype = ctypes.c_int

            self.rtl_cancel_async = self.rtllib.rtlsdr_cancel_async
            self.rtl_cancel_async.argtypes = [ctypes.c_void_p]
            self.rtl_cancel_async.restype = None

            self.rtl_set_freq_correction = self.rtllib.rtlsdr_set_freq_correction
            self.rtl_set_freq_correction.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self.rtl_set_freq_correction.restype = ctypes.c_int

            try:
                self.rtl_set_bias_tee = self.rtllib.rtlsdr_set_bias_tee
                self.rtl_set_bias_tee.argtypes = [ctypes.c_void_p, ctypes.c_int]
                self.rtl_set_bias_tee.restype = ctypes.c_int
            except AttributeError:
                self.rtl_set_bias_tee = self.no_set_bias_tee

        except OSError:
            raise RadioMissingLibrtlsdr("missing librtlsdr, or it is not in your library path.")

    def no_set_bias_tee(self, foo, bar):
        print("This version of librtlsdr does not support enabling bias-tee, please upgrade your librtlsdr")
        return 0

    def get_device_count(self):
        return self.rtl_get_device_count()

    def get_rtl_usb_info(self, index):
        # Allocate memory buffers
        usb_manuf = (ctypes.c_char * 256)()
        usb_product = (ctypes.c_char * 256)()
        usb_serial = (ctypes.c_char * 256)()
       
        # Call the library
        self.rtl_get_usb_strings(index, usb_manuf, usb_product, usb_serial)
       
        # If there's a smarter way to do this, patches welcome
        m = bytearray(usb_manuf)
        p = bytearray(usb_product)
        s = bytearray(usb_serial)

        # Return tuple
        return (m.partition(b'\0')[0].decode('UTF-8'), p.partition(b'\0')[0].decode('UTF-8'), s.partition(b'\0')[0].decode('UTF-8'))

    def cancel(self):
        self.rtl_cancel_async(self.rtlradio)

    def open_radio(self, rnum, frequency, rate, gain = -1, autogain = False, ppm = 0, biastee = -1):
        self.rtlradio = ctypes.c_void_p(0)

        r = self.rtl_open(ctypes.byref(self.rtlradio), rnum)
        if not r == 0:
            raise RadioOpenError("Could not open radio")

        if not gain < 0:
            r = self.rtl_set_tuner_gain_mode(self.rtlradio, 1)
            if not r == 0:
                raise RadioConfigError("Could not set tuner gain mode")

            r = self.rtl_set_tuner_gain(self.rtlradio, gain)
            if not r == 0:
                raise RadioConfigError("Could not set gain {}".format(gain))
        elif autogain:
            r = self.rtl_set_tuner_gain_mode(self.rtlradio, 0)
            if not r == 0:
                raise RadioConfigError("Could not set tuner gain mode")
            
            r = self.rtl_set_agc_mode(self.rtlradio, 1)
            if not r == 0:
                raise RadioConfigError("Could not set agc mode")

        r = self.rtl_set_center_freq(self.rtlradio, frequency)
        if not r == 0:
            raise RadioConfigError("Could not set frequency")

        r = self.rtl_set_sample_rate(self.rtlradio, rate)
        if not r == 0:
            raise RadioConfigError("Could not set rate")

        if not ppm == 0:
            r = self.rtl_set_freq_correction(self.rtlradio, ppm)
            if not r == 0:
                raise RadioConfigError("Could not set PPM correction")

        if biastee > 0:
            r = self.rtl_set_bias_tee(self.rtlradio, 1)
            if not r == 0:
                raise RadioConfigError("Could not set bias-tee")

        r = self.rtl_reset_buffer(self.rtlradio)
        if not r == 0:
            raise RadioConfigError("Could not reset radio buffer")

    def read_samples(self, callback, nbufs, bufsz):
        """
        Read samples, calling the callback 'callback' which must be a
        rtl_read_async_cb_t function.
        """
        
        rtl_read_async_cb = self.rtl_read_async_cb_t(callback)
        r = self.rtl_read_async(self.rtlradio, rtl_read_async_cb, None, nbufs, bufsz)

        if not r == 0:
            raise RadioOpenError(f"Error reading from rtlsdr: {r}")

    def get_rtl_usb_info(self, index):
        # Allocate memory buffers
        usb_manuf = (ctypes.c_char * 256)()
        usb_product = (ctypes.c_char * 256)()
        usb_serial = (ctypes.c_char * 256)()
       
        # Call the library
        self.rtl_get_usb_strings(index, usb_manuf, usb_product, usb_serial)
       
        # If there's a smarter way to do this, patches welcome
        m = bytearray(usb_manuf)
        p = bytearray(usb_product)
        s = bytearray(usb_serial)

        # Return tuple
        return (m.partition(b'\0')[0].decode('UTF-8'), p.partition(b'\0')[0].decode('UTF-8'), s.partition(b'\0')[0].decode('UTF-8'))



#ifdef DLL_EXPORT
#define DLL_FUNC __declspec(dllexport)
#else
#define DLL_FUNC __declspec(dllimport)
#endif /* DLL_EXPORT */


/*
 * Start a sensor receiving packets. Only one sensor should be active
 * at a time.
 */
DLL_FUNC int _StartSensor(char *SensorName);

/*
 * Stop the currently active sensor.
 */
DLL_FUNC int _StopSensor(void);

/*
 * Receive a packet from the sensor. On input Length is the size
 * of the Data array. On exit it is the number of bytes written into
 * Data, or zero if no packet is available.
 */
DLL_FUNC void _GetPacket(int *Length, unsigned char *Data);


#ifndef DIAGNOSTICS_H
#define DIAGNOSTICS_H

#include <libusb-1.0/libusb.h>

typedef struct {
    uint16_t vendor_id;
    uint16_t product_id;
    uint8_t device_class;
    uint8_t device_subclass;
    uint8_t device_protocol;
    int error; // Error code if any
} DeviceInfo;

// Function to scan USB devices and return their information
ssize_t scan_usb_devices(DeviceInfo **devices);

#endif // DIAGNOSTICS_H

#ifndef ACTIONS_H
#define ACTIONS_H

#include <libusb-1.0/libusb.h>

// Function to reset a USB device
int reset_device(libusb_device *dev);

// Function to repair a USB device
int repair_device(libusb_device *dev);

#endif // ACTIONS_H

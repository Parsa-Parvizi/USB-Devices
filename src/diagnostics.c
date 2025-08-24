#include "diagnostics.h"
#include "security.h"
#include <openssl/sha.h>

ssize_t scan_usb_devices(DeviceInfo **devices) {
    if (!check_system_permissions()) {
        return -1;
    }

    if (!authenticate_user()) {
        return -1;
    }

    libusb_device **devs;
    libusb_context *ctx = NULL;
    ssize_t cnt;

    if (libusb_init(&ctx) < 0) {
        log_activity("LIBUSB initialization failed");
        return -1;
    }

    cnt = libusb_get_device_list(ctx, &devs);
    if (cnt < 0) {
        libusb_exit(ctx);
        log_activity("Failed to get USB device list");
        return -1;
    }

    *devices = calloc(cnt, sizeof(DeviceInfo));
    if (*devices == NULL) {
        libusb_free_device_list(devs, 1);
        libusb_exit(ctx);
        return -1;
    }

    for (ssize_t i = 0; i < cnt; i++) {
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(devs[i], &desc) == 0) {
            (*devices)[i].vendor_id = desc.idVendor;
            (*devices)[i].product_id = desc.idProduct;
            (*devices)[i].device_class = desc.bDeviceClass;
            (*devices)[i].device_subclass = desc.bDeviceSubClass;
            (*devices)[i].device_protocol = desc.bDeviceProtocol;

            // Calculate device hash for integrity checking
            unsigned char device_hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, &desc, sizeof(desc));
            SHA256_Final(device_hash, &sha256);
            memcpy((*devices)[i].device_hash, device_hash, SHA256_DIGEST_LENGTH);

            (*devices)[i].error = 0;
        } else {
            (*devices)[i].error = -1;
            log_activity("Failed to read device descriptor");
        }
    }

    libusb_free_device_list(devs, 1);
    libusb_exit(ctx);

    char log_msg[100];
    snprintf(log_msg, sizeof(log_msg), "Scanned %zd USB devices", cnt);
    log_activity(log_msg);

    return cnt;
}

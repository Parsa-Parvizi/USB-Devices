#include "actions.h"
#include "security.h"
#include <unistd.h>

int reset_device(libusb_device *dev, const char *username) {
    if (!authenticate_user()) {
        return -1;
    }

    if (!rate_limit_operation("reset", username)) {
        printf("❌ Rate limit exceeded for reset operations\n");
        return -1;
    }

    if (!confirm_operation("reset USB device")) {
        log_activity("Reset operation cancelled by user");
        return 0;
    }

    // Simulate reset (replace with actual libusb_reset_device)
    printf("🔄 Resetting device...\n");
    sleep(2);

    log_activity("USB device reset successfully");
    return 0;
}

int repair_device(libusb_device *dev, const char *username) {
    if (!authenticate_user()) {
        return -1;
    }

    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(dev, &desc) != 0) {
        log_activity("Failed to get device descriptor for repair");
        return -1;
    }

    if (!is_device_whitelisted(desc.idVendor, desc.idProduct)) {
        printf("❌ Device not whitelisted for repair operations\n");
        log_activity("Attempted repair on non-whitelisted device");
        return -1;
    }

    if (!rate_limit_operation("repair", username)) {
        printf("❌ Rate limit exceeded for repair operations\n");
        return -1;
    }

    if (!confirm_operation("repair USB device")) {
        log_activity("Repair operation cancelled by user");
        return 0;
    }

    // Simulate repair process
    printf("🔧 Repairing device...\n");
    for (int i = 0; i < 3; i++) {
        printf("Step %d/3: Performing repair operation...\n", i + 1);
        sleep(1);
    }

    log_activity("USB device repair completed successfully");
    return 0;
}

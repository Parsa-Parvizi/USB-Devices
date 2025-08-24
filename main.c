#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "diagnostics.h"
#include "actions.h"
#include "security.h"

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  --list              List all USB devices\n");
    printf("  --repair VID:PID    Repair specific device (requires authentication)\n");
    printf("  --simulate          Simulate operations without actual changes\n");
    printf("  --help              Show this help message\n");
}

int main(int argc, char *argv[]) {
    // Initialize security module
    security_init();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Check if running as root
    if (geteuid() != 0) {
        printf("❌ This program must be run as root for USB operations\n");
        return 1;
    }

    if (strcmp(argv[1], "--list") == 0) {
        DeviceInfo *devices = NULL;
        ssize_t device_count = scan_usb_devices(&devices);

        if (device_count < 0) {
            printf("Error scanning USB devices.\n");
            return 1;
        }

        printf("🔍 Found %zd USB devices:\n", device_count);
        for (ssize_t i = 0; i < device_count; i++) {
            if (devices[i].error == 0) {
                printf("Device %zd: VID=%04x, PID=%04x, Class=%02x\n",
                       i, devices[i].vendor_id, devices[i].product_id, devices[i].device_class);
            } else {
                printf("Device %zd: ❌ Error reading descriptor\n", i);
            }
        }

        secure_memory_cleanup(devices, device_count * sizeof(DeviceInfo));
    }
    else if (strcmp(argv[1], "--repair") == 0 && argc == 3) {
        if (!authenticate_user()) {
            printf("❌ Authentication failed\n");
            return 1;
        }

        uint16_t vendor_id, product_id;
        if (sscanf(argv[2], "%hx:%hx", &vendor_id, &product_id) != 2) {
            printf("❌ Invalid format. Use VID:PID (hexadecimal)\n");
            return 1;
        }

        printf("🔧 Attempting repair for device %04x:%04x\n", vendor_id, product_id);
        // Actual repair logic would go here
    }
    else if (strcmp(argv[1], "--simulate") == 0) {
        printf("🔒 Simulation mode activated - no actual changes will be made\n");
        // Simulation logic
    }
    else if (strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
    }
    else {
        printf("❌ Invalid command or arguments\n");
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}

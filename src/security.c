#include "security.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

#define LOG_FILE "logs/usb_diag.log.enc"
#define AUTH_TIMEOUT 300 // 5 minutes

typedef struct {
    uint16_t vendor_id;
    uint16_t product_id;
    unsigned char expected_hash[32]; // SHA256 of device descriptor
} WhitelistedDevice;

typedef struct {
    time_t timestamp;
    char operation[50];
    char username[50];
    int success;
} OperationRecord;

// Encryption key (should be stored securely in production)
const unsigned char encryption_key[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

// Authorized users (should be loaded from secure config in production)
UserAccount authorized_users[] = {
        {"admin", {0}, 1}, // Password hash will be set at runtime
        {"operator", {0}, 0}
};
size_t authorized_users_count = 2;

WhitelistedDevice whitelist[MAX_WHITELISTED_DEVICES];
size_t whitelist_count = 0;
OperationRecord operation_history[100];
size_t operation_count = 0;
time_t last_auth_time = 0;

// Initialize security module
void security_init() {
    // Set admin password hash (sha256 of "securepassword123")
    unsigned char admin_hash[] = {
            0x8d, 0x96, 0x9e, 0xef, 0x6e, 0xca, 0x8c, 0x4f,
            0x93, 0xad, 0x41, 0x91, 0x5a, 0x49, 0x94, 0x61,
            0x5e, 0x89, 0x04, 0xe3, 0x0f, 0x85, 0x94, 0x5c,
            0x77, 0x33, 0x52, 0x23, 0x87, 0x4f, 0x43, 0x4b
    };
    memcpy(authorized_users[0].password_hash, admin_hash, 32);

    // Set operator password hash
    unsigned char operator_hash[] = {
            0x60, 0x3d, 0xae, 0x7d, 0x4e, 0x1d, 0x3e, 0x89,
            0x8d, 0x2c, 0x7a, 0x1f, 0x85, 0x2f, 0x9d, 0x38,
            0xeb, 0x35, 0xcd, 0x66, 0x4f, 0x84, 0x2a, 0x2d,
            0x2a, 0x0b, 0x8a, 0xce, 0x86, 0x2e, 0x43, 0x53
    };
    memcpy(authorized_users[1].password_hash, operator_hash, 32);
}

int authenticate_user() {
    if (time(NULL) - last_auth_time < AUTH_TIMEOUT) {
        return 1; // Already authenticated
    }

    char username[50];
    char password[50];
    int attempts = 0;

    printf("🔐 Authentication Required\n");

    while (attempts < MAX_PASSWORD_ATTEMPTS) {
        printf("Username: ");
        if (fgets(username, sizeof(username), stdin) == NULL) {
            return 0;
        }
        username[strcspn(username, "\n")] = 0;

        printf("Password: ");
        if (fgets(password, sizeof(password), stdin) == NULL) {
            return 0;
        }
        password[strcspn(password, "\n")] = 0;

        // Calculate password hash
        unsigned char input_hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)password, strlen(password), input_hash);

        // Find user and verify
        for (size_t i = 0; i < authorized_users_count; i++) {
            if (strcmp(username, authorized_users[i].username) == 0) {
                if (memcmp(input_hash, authorized_users[i].password_hash, SHA256_DIGEST_LENGTH) == 0) {
                    last_auth_time = time(NULL);
                    log_activity("User authenticated successfully");
                    return 1;
                }
            }
        }

        attempts++;
        printf("❌ Authentication failed. Attempts remaining: %d\n", MAX_PASSWORD_ATTEMPTS - attempts);
        sleep(2); // Delay to prevent brute force
    }

    log_activity("Authentication failed - too many attempts");
    return 0;
}

int encrypt_log(const char *plaintext, EncryptedLog *encrypted_log) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char iv[16];

    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, encryption_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    size_t plaintext_len = strlen(plaintext);
    unsigned char *ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE);

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, plaintext_len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, encrypted_log->tag) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    memcpy(encrypted_log->iv, iv, 16);
    encrypted_log->ciphertext_len = ciphertext_len;
    memcpy(encrypted_log + sizeof(EncryptedLog), ciphertext, ciphertext_len);

    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

void log_activity(const char *message) {
    char sanitized_message[512];
    strncpy(sanitized_message, message, sizeof(sanitized_message) - 1);
    sanitized_message[sizeof(sanitized_message) - 1] = '\0';
    sanitize_input(sanitized_message);

    EncryptedLog encrypted_log;
    if (encrypt_log(sanitized_message, &encrypted_log)) {
        FILE *log_file = fopen(LOG_FILE, "ab");
        if (log_file) {
            fwrite(&encrypted_log, sizeof(EncryptedLog), 1, log_file);
            fwrite((char*)&encrypted_log + sizeof(EncryptedLog), encrypted_log.ciphertext_len, 1, log_file);
            fclose(log_file);

            // Set secure permissions
            chmod(LOG_FILE, 0600);
        }
    }
}

int rate_limit_operation(const char *operation, const char *username) {
    time_t now = time(NULL);
    int count = 0;

    for (size_t i = 0; i < operation_count; i++) {
        if (now - operation_history[i].timestamp < RATE_LIMIT_WINDOW &&
            strcmp(operation_history[i].operation, operation) == 0 &&
            strcmp(operation_history[i].username, username) == 0) {
            count++;
        }
    }

    if (count >= MAX_OPERATIONS_PER_WINDOW) {
        log_activity("Rate limit exceeded for operation");
        return 0;
    }

    // Add to history
    if (operation_count < sizeof(operation_history) / sizeof(OperationRecord)) {
        operation_history[operation_count].timestamp = now;
        strncpy(operation_history[operation_count].operation, operation, 49);
        strncpy(operation_history[operation_count].username, username, 49);
        operation_history[operation_count].success = 1;
        operation_count++;
    }

    return 1;
}

void sanitize_input(char *input) {
    for (size_t i = 0; input[i] != '\0'; i++) {
        if (input[i] < 32 || input[i] > 126) {
            input[i] = '?';
        }
        // Prevent injection attacks
        if (strstr(input, "../") || strstr(input, "..\\")) {
            input[i] = '?';
        }
    }
}

int check_system_permissions() {
    if (geteuid() != 0) {
        printf("❌ Root privileges required for USB operations\n");
        return 0;
    }
    return 1;
}

void secure_memory_cleanup(void *ptr, size_t size) {
    if (ptr) {
        memset(ptr, 0, size);
        free(ptr);
    }
}

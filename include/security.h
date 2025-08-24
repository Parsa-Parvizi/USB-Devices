#ifndef SECURITY_H
#define SECURITY_H

#include <libusb-1.0/libusb.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_WHITELISTED_DEVICES 50
#define MAX_PASSWORD_ATTEMPTS 3
#define RATE_LIMIT_WINDOW 60 // 60 seconds
#define MAX_OPERATIONS_PER_WINDOW 5

// Structure for encrypted logging
typedef struct {
    unsigned char iv[16];
    unsigned char tag[16];
    size_t ciphertext_len;
} EncryptedLog;

// Structure for user authentication
typedef struct {
    char username[50];
    unsigned char password_hash[32]; // SHA256
    int is_admin;
} UserAccount;

// Function prototypes
int is_device_whitelisted(uint16_t vendor_id, uint16_t product_id);
int confirm_operation(const char *operation);
int authenticate_user();
int rate_limit_operation(const char *operation, const char *username);
int validate_device_integrity(libusb_device *dev);
int encrypt_log(const char *plaintext, EncryptedLog *encrypted_log);
int decrypt_log(const EncryptedLog *encrypted_log, char *plaintext);
int verify_device_signature(libusb_device *dev);
void sanitize_input(char *input);
int check_system_permissions();
void secure_memory_cleanup(void *ptr, size_t size);

// Security configuration
extern const unsigned char encryption_key[32];
extern UserAccount authorized_users[];
extern size_t authorized_users_count;

#endif // SECURITY_H

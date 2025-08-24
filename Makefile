CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -O2 -fstack-protector-strong
LDFLAGS = -lusb-1.0 -lcrypto -lssl
SRC = src/diagnostics.c src/actions.c src/security.c src/main.c
OBJ = $(SRC:.c=.o)
TARGET = usb_diagnostic

# Security flags
SECURITY_FLAGS = -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) -o $@ $^ $(LDFLAGS)
	strip --strip-all $(TARGET) # Remove debug symbols for security

%.o: %.c
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) -c $< -o $@

install: $(TARGET)
	install -m 0755 -o root -g root $(TARGET) /usr/local/bin/
	install -m 0700 -o root -g root -d /var/log/usb_diagnostic

clean:
	rm -f $(OBJ) $(TARGET)
	find . -name "*.enc" -delete

security-check:
	checksec --file=$(TARGET)

.PHONY: all clean install security-check
CC = gcc
CFLAGS = -Wall -Wextra -O2
LDLIBS = -lssl -lcrypto

device_client: device_client.c
	$(CC) $(CFLAGS) -o device_client device_client.c $(LDLIBS)

clean:
	rm -f device_client

.PHONY: clean

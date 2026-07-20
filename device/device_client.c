#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define BUF_SIZE 512

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

/* Converts a hex string like "a1b2c3" into raw bytes, returns byte count. */
static int hex_to_bytes(const char *hex, unsigned char *out, int out_max) {
    int len = (int)strlen(hex) / 2;
    if (len > out_max) len = out_max;
    for (int i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &out[i]);
    }
    return len;
}

static void bytes_to_hex(const unsigned char *bytes, int len, char *out) {
    for (int i = 0; i < len; i++) {
        sprintf(out + 2 * i, "%02x", bytes[i]);
    }
    out[2 * len] = '\0';
}

/* Reads one newline-terminated line from fd into buf. Returns bytes read, -1 on EOF/error. */
static int read_line(int fd, char *buf, int bufsize) {
    int n = 0;
    while (n < bufsize - 1) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) return -1;
        if (c == '\n') break;
        buf[n++] = c;
    }
    buf[n] = '\0';
    return n;
}

/* write() can do partial writes on a socket, so loop until everything is sent. */
static void send_line(int fd, const char *line) {
    size_t len = strlen(line);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, line + sent, len - sent);
        if (n <= 0) die("write");
        sent += (size_t)n;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <server_ip> <port> <device_id> <secret_hex>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    int port = atoi(argv[2]);
    const char *device_id = argv[3];
    const char *secret_hex = argv[4];

    unsigned char secret[64];
    int secret_len = hex_to_bytes(secret_hex, secret, sizeof(secret));

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) die("socket");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) != 1) die("inet_pton");

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("connect");
    printf("[device] connected to %s:%d as '%s'\n", server_ip, port, device_id);

    char buf[BUF_SIZE];

    /* Step 1: announce ourselves */
    snprintf(buf, sizeof(buf), "HELLO %s\n", device_id);
    send_line(sock, buf);

    /* Step 2: receive CHALLENGE <nonce_hex> <timestamp> */
    if (read_line(sock, buf, sizeof(buf)) <= 0) die("read (challenge)");
    printf("[device] <- %s\n", buf);

    char cmd[16], nonce_hex[64], timestamp_str[32];
    if (sscanf(buf, "%15s %63s %31s", cmd, nonce_hex, timestamp_str) != 3 ||
        strcmp(cmd, "CHALLENGE") != 0) {
        fprintf(stderr, "[device] unexpected reply, aborting\n");
        close(sock);
        return 1;
    }

    /* Step 3: prove we hold the secret without sending it -
       HMAC-SHA256(secret, "device_id|nonce|timestamp") */
    char message[256];
    snprintf(message, sizeof(message), "%s|%s|%s", device_id, nonce_hex, timestamp_str);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    HMAC(EVP_sha256(), secret, secret_len,
         (unsigned char *)message, strlen(message), digest, &digest_len);

    char digest_hex[2 * EVP_MAX_MD_SIZE + 1];
    bytes_to_hex(digest, (int)digest_len, digest_hex);

    /* Step 4: send the proof */
    snprintf(buf, sizeof(buf), "RESPONSE %s\n", digest_hex);
    send_line(sock, buf);

    /* Step 5: read the verdict */
    if (read_line(sock, buf, sizeof(buf)) <= 0) die("read (auth result)");
    printf("[device] <- %s\n", buf);

    char session_token[64] = {0};
    if (sscanf(buf, "AUTH_OK %63s", session_token) == 1) {
        printf("[device] authenticated, session token: %s\n", session_token);

        /* Step 6: send one simulated sensor reading, tagged with the session token */
        double simulated_temperature_c = 24.7;
        snprintf(buf, sizeof(buf), "DATA %s temp=%.1f\n", session_token, simulated_temperature_c);
        send_line(sock, buf);

        if (read_line(sock, buf, sizeof(buf)) > 0) {
            printf("[device] <- %s\n", buf);
        }
    } else {
        printf("[device] authentication failed, closing connection\n");
    }

    send_line(sock, "BYE\n");
    close(sock);
    return 0;
}

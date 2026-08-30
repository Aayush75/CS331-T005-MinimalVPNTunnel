#include "udp.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int udp_open(const char *bind_ip, uint16_t bind_port)
{
    int fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("socket: %s", strerror(errno));
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bind_port);
    if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
        log_error("bad bind IPv4 address: %s", bind_ip);
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("bind %s:%u: %s", bind_ip, bind_port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int udp_send_to(int fd, const char *peer_ip, uint16_t peer_port,
                const uint8_t *buf, size_t n)
{
    struct sockaddr_in addr;
    ssize_t sent;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer_port);
    if (inet_pton(AF_INET, peer_ip, &addr.sin_addr) != 1) {
        log_error("bad peer IPv4 address: %s", peer_ip);
        return -1;
    }

    do {
        sent = sendto(fd, buf, n, 0, (struct sockaddr *)&addr, sizeof(addr));
    } while (sent < 0 && errno == EINTR);

    if (sent < 0) {
        log_warn("sendto: %s", strerror(errno));
        return -1;
    }
    if ((size_t)sent != n) {
        log_warn("sendto short write %zd/%zu", sent, n);
        return -1;
    }
    return 0;
}

ssize_t udp_recv_from(int fd, uint8_t *buf, size_t cap,
                      char *src_ip, size_t src_ip_cap, uint16_t *src_port)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    ssize_t n;

    do {
        n = recvfrom(fd, buf, cap, 0, (struct sockaddr *)&addr, &alen);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        log_warn("recvfrom: %s", strerror(errno));
        return -1;
    }
    if (src_port != NULL) {
        *src_port = ntohs(addr.sin_port);
    }
    if (src_ip != NULL && src_ip_cap > 0) {
        if (inet_ntop(AF_INET, &addr.sin_addr, src_ip, src_ip_cap) == NULL) {
            src_ip[0] = '\0';
        }
    }
    return n;
}

int peer_is_expected(const char *got_ip, uint16_t got_port,
                     const char *exp_ip, uint16_t exp_port)
{
    return got_port == exp_port && got_ip != NULL && exp_ip != NULL &&
           strcmp(got_ip, exp_ip) == 0;
}

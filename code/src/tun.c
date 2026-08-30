#include "tun.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int tun_open(const char *name)
{
    struct ifreq ifr;
    int fd;

    if (name == NULL || name[0] == '\0') {
        log_error("TUN name is empty");
        return -1;
    }

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        log_error("open /dev/net/tun: %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (strlen(name) >= IFNAMSIZ) {
        log_error("TUN name too long: %s", name);
        close(fd);
        return -1;
    }
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        log_error("TUNSETIFF %s: %s", name, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

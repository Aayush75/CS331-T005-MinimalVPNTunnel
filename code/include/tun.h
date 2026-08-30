#ifndef SVPN_TUN_H
#define SVPN_TUN_H

/* Attach to an already-created persistent TUN device (IFF_TUN | IFF_NO_PI). */
int tun_open(const char *name);

#endif /* SVPN_TUN_H */

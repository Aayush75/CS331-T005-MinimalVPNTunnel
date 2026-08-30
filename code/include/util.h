#ifndef SVPN_UTIL_H
#define SVPN_UTIL_H

#include "common.h"

#include <sys/types.h>

extern int g_verbose;

void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_verbose(const char *fmt, ...);

void put_u16be(uint8_t *p, uint16_t v);
void put_u64be(uint8_t *p, uint64_t v);
uint16_t get_u16be(const uint8_t *p);
uint64_t get_u64be(const uint8_t *p);

int parse_port(const char *s, uint16_t *out);
void hex_encode(const uint8_t *in, size_t n, char *out, size_t outcap);
uint64_t monotonic_ms(void);
ssize_t write_full(int fd, const uint8_t *buf, size_t n);

#endif /* SVPN_UTIL_H */

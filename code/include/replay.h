#ifndef SVPN_REPLAY_H
#define SVPN_REPLAY_H

#include "common.h"

struct replay_window {
    uint64_t highest;
    uint64_t bitmap; /* bit 0 = highest, bit k = highest-k */
    int initialized;
};

void replay_init(struct replay_window *w);

/* 0 = accept (state updated), -1 = reject (state unchanged). */
int replay_check_update(struct replay_window *w, uint64_t seq);

#endif /* SVPN_REPLAY_H */

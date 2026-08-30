#include "replay.h"

void replay_init(struct replay_window *w)
{
    w->highest = 0;
    w->bitmap = 0;
    w->initialized = 0;
}

int replay_check_update(struct replay_window *w, uint64_t seq)
{
    uint64_t shift;
    uint64_t delta;
    uint64_t bit;

    if (w == NULL || seq == 0) {
        return -1;
    }

    if (!w->initialized) {
        w->highest = seq;
        w->bitmap = 1ULL; /* bit 0 = highest */
        w->initialized = 1;
        return 0;
    }

    if (seq > w->highest) {
        shift = seq - w->highest;
        if (shift >= 64) {
            w->bitmap = 0;
        } else {
            w->bitmap <<= shift;
        }
        w->bitmap |= 1ULL;
        w->highest = seq;
        return 0;
    }

    delta = w->highest - seq;
    if (delta >= 64) {
        return -1; /* older than the 64-packet window */
    }
    bit = 1ULL << delta;
    if (w->bitmap & bit) {
        return -1; /* duplicate */
    }
    w->bitmap |= bit;
    return 0;
}

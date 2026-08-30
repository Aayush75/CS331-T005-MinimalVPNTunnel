#include "test_harness.h"
#include "replay.h"

#include <stdint.h>

void test_replay(void)
{
    struct replay_window w;
    uint64_t i;

    replay_init(&w);
    ASSERT_EQ_INT(replay_check_update(&w, 1), 0);          /* first accepted */
    ASSERT_EQ_INT(replay_check_update(&w, 1), -1);         /* immediate duplicate */
    ASSERT_EQ_INT(replay_check_update(&w, 2), 0);
    ASSERT_EQ_INT(replay_check_update(&w, 3), 0);
    ASSERT_EQ_INT(replay_check_update(&w, 5), 0);          /* skip 4 */
    ASSERT_EQ_INT(replay_check_update(&w, 4), 0);          /* reorder inside window */
    ASSERT_EQ_INT(replay_check_update(&w, 4), -1);         /* repeated reorder */
    ASSERT_EQ_INT(replay_check_update(&w, 3), -1);

    /* Fill forward so highest = 70, window is [7, 70] (64 packets: 70 down to 7) */
    replay_init(&w);
    ASSERT_EQ_INT(replay_check_update(&w, 70), 0);
    ASSERT_EQ_INT(replay_check_update(&w, 7), 0);          /* highest-63 */
    ASSERT_EQ_INT(replay_check_update(&w, 6), -1);         /* exactly outside */

    /* large forward jump */
    replay_init(&w);
    ASSERT_EQ_INT(replay_check_update(&w, 1), 0);
    ASSERT_EQ_INT(replay_check_update(&w, 100), 0);
    ASSERT_EQ_INT(replay_check_update(&w, 1), -1);
    /* 100-63=37 is the oldest sequence still inside the 64-packet window */

    replay_init(&w);
    ASSERT_EQ_INT(replay_check_update(&w, 1), 0);
    ASSERT_EQ_INT(replay_check_update(&w, 100), 0);
    ASSERT_EQ_INT(replay_check_update(&w, 37), 0);
    ASSERT_EQ_INT(replay_check_update(&w, 36), -1);

    /* shift exactly 64: highest 1 -> 65, old 1 is outside */
    replay_init(&w);
    ASSERT_EQ_INT(replay_check_update(&w, 1), 0);
    ASSERT_EQ_INT(replay_check_update(&w, 65), 0);
    ASSERT_EQ_INT(replay_check_update(&w, 1), -1);
    ASSERT_EQ_INT(replay_check_update(&w, 2), 0);          /* 65-63=2 */

    /* monotonically increasing */
    replay_init(&w);
    for (i = 1; i <= 200; i++) {
        ASSERT_EQ_INT(replay_check_update(&w, i), 0);
    }

    /* uint64 edges */
    replay_init(&w);
    ASSERT_EQ_INT(replay_check_update(&w, UINT64_MAX), 0);
    ASSERT_EQ_INT(replay_check_update(&w, UINT64_MAX), -1);
    ASSERT_EQ_INT(replay_check_update(&w, UINT64_MAX - 1), 0);
    ASSERT_EQ_INT(replay_check_update(&w, UINT64_MAX - 63), 0);
    ASSERT_EQ_INT(replay_check_update(&w, UINT64_MAX - 64), -1);

    replay_init(&w);
    ASSERT_EQ_INT(replay_check_update(&w, UINT64_MAX - 5), 0);
    ASSERT_EQ_INT(replay_check_update(&w, UINT64_MAX), 0);

    ASSERT_EQ_INT(replay_check_update(&w, 0), -1);
}

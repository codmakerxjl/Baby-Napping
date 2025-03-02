/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <cassert>

#ifndef SE_GLOBALS
#define SE_GLOBALS()
#endif

#ifndef SE_TARGET_STATE
#define SE_TARGET_STATE(x) assert(!x)
#endif

#ifndef SE_STEP
int score = 0;
#define SE_STEP(x) printf("Reached Checkpoint %d\n", score++);
#endif
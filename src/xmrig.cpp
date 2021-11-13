/* XMRig
 * Copyright (c) 2018-2021 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2021 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "App.h"
#include "base/kernel/Entry.h"
#include "base/kernel/Process.h"
#include "crypto/ghostrider/ghostrider.h"
#include "crypto/cn/CnCtx.h"
#include "crypto/common/VirtualMemory.h"
#include <random>
#include <chrono>


int main(int argc, char **argv)
{
    using namespace xmrig;

#if 0
    VirtualMemory::init(0, 1U << 21);
    VirtualMemory* memory = new VirtualMemory(1U << 21, true, false, false);
    if (memory->isHugePages()) {
        printf("Using huge pages\n");
    }
    cryptonight_ctx* ctx[2];
    CnCtx::create(ctx, memory->scratchpad(), 1U << 21, 1);

    uint8_t input[36] = "test";
    uint8_t hash[32] = {};
    uint8_t acc_hash[32] = {};

    using namespace std::chrono;
    const system_clock::time_point start_time = system_clock::now();

    for (int k = 0; k < 1000; ++k) {
        std::mt19937_64 r(k);
        uint8_t seed[32] = {};
        for (int i = 0; i < 32; ++i) {
            seed[i] = r();
        }
        memcpy(input + sizeof(input) - sizeof(seed), seed, sizeof(seed));
        ghostrider::hash_single(ctx, input, sizeof(input), hash);
        for (int i = 0; i < 32; ++i) acc_hash[i] ^= hash[i];
    }

    const double elapsed_time = duration_cast<nanoseconds>(system_clock::now() - start_time).count() / 1e9;
    printf("%f seconds\n%f h/s\n", elapsed_time, 1000 / elapsed_time);

    // de89288c6af30ee8923b9bad27cb2e1f51018737ec26245129bf202fd0249017
    for (int i = 31; i >= 0; --i) printf("%02x", acc_hash[i]);
    printf("\n");

    return 0;
#else
    Process process(argc, argv);
    const Entry::Id entry = Entry::get(process);
    if (entry) {
        return Entry::exec(process, entry);
    }

    App app(&process);

    return app.exec();
#endif
}

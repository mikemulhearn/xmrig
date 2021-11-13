/* XMRig
 * Copyright 2018-2021 SChernykh   <https://github.com/SChernykh>
 * Copyright 2016-2021 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
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


#include "ghostrider.h"
#include "sph_blake.h"
#include "sph_bmw.h"
#include "sph_groestl.h"
#include "sph_jh.h"
#include "sph_keccak.h"
#include "sph_skein.h"
#include "sph_luffa.h"
#include "sph_cubehash.h"
#include "sph_shavite.h"
#include "sph_simd.h"
#include "sph_echo.h"
#include "sph_hamsi.h"
#include "sph_fugue.h"
#include "sph_shabal.h"
#include "sph_whirlpool.h"
#include "crypto/cn/CnHash.h"


#define CORE_HASH(i, x) static void h##i(const uint8_t* data, size_t size, uint8_t* output) \
{ \
    sph_##x##_context ctx; \
    sph_##x##_init(&ctx); \
    sph_##x(&ctx, data, size); \
    sph_##x##_close(&ctx, output); \
}

CORE_HASH( 0, blake512   );
CORE_HASH( 1, bmw512     );
CORE_HASH( 2, groestl512 );
CORE_HASH( 3, jh512      );
CORE_HASH( 4, keccak512  );
CORE_HASH( 5, skein512   );
CORE_HASH( 6, luffa512   );
CORE_HASH( 7, cubehash512);
CORE_HASH( 8, shavite512 );
CORE_HASH( 9, simd512    );
CORE_HASH(10, echo512    );
CORE_HASH(11, hamsi512   );
CORE_HASH(12, fugue512   );
CORE_HASH(13, shabal512  );
CORE_HASH(14, whirlpool  );

#undef CORE_HASH

typedef void (*core_hash_func)(const uint8_t* data, size_t size, uint8_t* output);
static const core_hash_func core_hash[15] = { h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14 };


namespace xmrig
{


static constexpr Algorithm::Id cn_hash[6] = {
    Algorithm::CN_GR_0,
    Algorithm::CN_GR_1,
    Algorithm::CN_GR_2,
    Algorithm::CN_GR_3,
    Algorithm::CN_GR_4,
    Algorithm::CN_GR_5,
};

template<size_t N>
static inline void select_indices(uint32_t (&indices)[N], const uint8_t* seed)
{
    bool selected[N] = {};

    uint32_t k = 0;
    for (uint32_t i = 0; i < 64; ++i) {
        const uint8_t index = ((seed[i / 2] >> ((i & 1) * 4)) & 0xF) % N;
        if (!selected[index]) {
            selected[index] = true;
            indices[k++] = index;
            if (k >= N) {
                return;
            }
        }
    }

    for (uint32_t i = 0; i < N; ++i) {
        if (!selected[i]) {
            indices[k++] = i;
        }
    }
}


namespace ghostrider
{


void hash_single(cryptonight_ctx** ctx, const uint8_t* data, size_t size, uint8_t* output)
{
    // PrevBlockHash (GhostRider's seed) is stored in bytes [4; 36)
    const uint8_t* seed = data + 4;

    uint32_t core_indices[15];
    select_indices(core_indices, seed);

    uint32_t cn_indices[6];
    select_indices(cn_indices, seed);

    uint8_t tmp[64];
    core_hash[core_indices[0]](data, size, tmp);

    for (int i = 1; i < 5; ++i) {
        core_hash[core_indices[i]](tmp, 64, tmp);
    }

    CnHash::fn(cn_hash[cn_indices[0]], CnHash::AV_SINGLE, Assembly::AUTO)(tmp, 64, tmp, ctx, 0);
    memset(tmp + 32, 0, 32);

    for (int i = 5; i < 10; ++i) {
        core_hash[core_indices[i]](tmp, 64, tmp);
    }

    CnHash::fn(cn_hash[cn_indices[1]], CnHash::AV_SINGLE, Assembly::AUTO)(tmp, 64, tmp, ctx, 0);
    memset(tmp + 32, 0, 32);

    for (int i = 10; i < 15; ++i) {
        core_hash[core_indices[i]](tmp, 64, tmp);
    }

    CnHash::fn(cn_hash[cn_indices[2]], CnHash::AV_SINGLE, Assembly::AUTO)(tmp, 64, tmp, ctx, 0);
    memcpy(output, tmp, 32);
}


} // namespace ghostrider


} // namespace xmrig

#include <miner.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "RandomX/src/bytecode_machine.hpp"
#include "RandomX/src/dataset.hpp"
#include "RandomX/src/blake2/endian.h"
#include "RandomX/src/blake2/blake2.h"
#include "RandomX/src/blake2_generator.hpp"
#include "RandomX/src/superscalar.hpp"
#include "RandomX/src/reciprocal.h"
#include "RandomX/src/intrin_portable.h"
#include "RandomX/src/jit_compiler.hpp"
#include "RandomX/src/aes_hash.hpp"
#include "RandomX/src/randomx.h"
#include <openssl/sha.h>
#include "uint256.h"

#include <cassert>

extern "C" {
void randomx_init(int thr_id);
}

void randomx_initseed();
void randomx_initcache(int thr_id);
void randomx_initdataset(int thr_id);
void randomx_initvm(int thr_id);
void randomx_shutoff(int thr_id);
void seedNow(int nHeight);
void seedHash(uint256 &seed, char *seedStr, int nHeight);
void randomxhash(void *output, const void *input, int thr_id = 0);

//! barrystyle 03032020
uint256 oldCache;
char keyCache[32];
unsigned int seedHeight;

//! vector to hold thread obj
std::vector<randomx_flags> vecFlag;
std::vector<randomx_cache*> vecCache;
std::vector<randomx_dataset*> vecDataset;
std::vector<randomx_vm*> vecVm;

// TODO: CALL THIS!
extern "C" {
void randomx_init(int thr_id)
{
    randomx_initseed();
    for (int i=0; i<thr_id; i++) {
       randomx_initcache(i);
       randomx_initdataset(i);
       randomx_initvm(i);
    }
}
}

void randomx_initseed()
{
    seedHash(oldCache,keyCache,1);
}

void randomx_initcache(int thr_id)
{
    printf("%s - instance %d\n", __func__, thr_id);
    randomx_flags flags = randomx_get_flags();
    vecFlag.push_back(flags);
    randomx_cache *cache = randomx_alloc_cache(vecFlag.at(thr_id) | RANDOMX_FLAG_LARGE_PAGES);
    if (!cache)
        cache = randomx_alloc_cache(flags);
    randomx_init_cache(cache, &keyCache, 32);
    vecCache.push_back(cache);
}

void randomx_initdataset(int thr_id)
{
    printf("%s - instance %d\n", __func__, thr_id);
    randomx_dataset *dataset = randomx_alloc_dataset(RANDOMX_FLAG_LARGE_PAGES);
    if (!dataset)
        dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
    randomx_init_dataset(dataset, vecCache.at(thr_id), 0, randomx_dataset_item_count());
    vecDataset.push_back(dataset);
}

void randomx_initvm(int thr_id)
{
    printf("%s - instance %d\n", __func__, thr_id);
    randomx_vm *vm = randomx_create_vm(vecFlag.at(thr_id), vecCache.at(thr_id), vecDataset.at(thr_id));
    vecVm.push_back(vm);
}

void seedNow(int nHeight)
{
    uint256 tempCache;
    char tempStr[64];
    seedHash(tempCache, tempStr, nHeight);
    if (!memcmp(&tempCache,keyCache,32)) {
        printf("* changed seed at height %d\n", nHeight);
        memcpy(keyCache,&tempCache,32);
    }
}

void seedHash(uint256 &seed, char *seedStr, int nHeight)
{
    char seedHalf[32] = {0};
    int seedInt = (((nHeight+99)/100)+100);
    sprintf(seedHalf,"%d",seedInt);
    SHA256((const unsigned char*)seedHalf,32,(unsigned char*)seedHalf);
    memcpy(&seed,seedHalf,32);
    for (unsigned int i=0; i<32; i++)
        sprintf(seedStr+(i*2),"%02hhx", seedHalf[i]);
}

// Produce a 32-byte hash from 80-byte input data, using given VM from the vector of 'em
void randomxhash(void *output, const void *input, int thr_id)
{
    unsigned char _ALIGN(32) hash[32];
    randomx_calculate_hash(vecVm.at(thr_id), input, 80, hash);
    memcpy(output, hash, 32);
}

// Scan driver
extern "C" {
int scanhash_randomx(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], nonce);
		randomxhash(hash, endiandata, thr_id);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
}
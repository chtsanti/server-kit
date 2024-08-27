/*
 *  Copyright (C) 2004-2008 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA.
 */

#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>
#include <pthread.h>

#include <atomic>
#include <cmath>

#include "Debug.h"
#include "EventLoop.h"
#include "mem.h"
#include <iostream>
#include <sstream>
#include <cstring>


struct _ci_align_test {char n[1]; double d;};
#define _CI_NBYTES_ALIGNMENT ((size_t) &(((struct _ci_align_test *)0)[0].d))
#define _CI_ALIGN(val) ((val+(_CI_NBYTES_ALIGNMENT - 1))&~(_CI_NBYTES_ALIGNMENT - 1))

int ci_buffers_init();

/*General Functions */
const char *MEMPOOLS_STAT_MASTER_GROUP = "Memory Pools";
ci_mem_allocator_t *default_allocator = NULL;
static int MEM_ALLOCATOR_POOL = -1;
static int PACK_ALLOCATOR_POOL = -1;
bool ZeroMemBeforeRelease = true;
bool CheckDuplicateFrees = false;

static size_t sizeof_pack_allocator();
ci_mem_allocator_t *ci_create_pool_allocator(const char *name, size_t items_size);
size_t  pool_allocator_objects_size(const ci_mem_allocator_t *allocator);
size_t  pool_allocator_objects_metadata_size();

int ci_mem_init()
{
    int ret = -1;

    ret = ci_buffers_init();

    default_allocator = ci_create_os_allocator();
    if (!default_allocator && ret ==-1)
        ret = 0;

    MEM_ALLOCATOR_POOL = ci_object_pool_register("ci_mem_allocator_t", sizeof(ci_mem_allocator_t));
    assert(MEM_ALLOCATOR_POOL >= 0);

    PACK_ALLOCATOR_POOL = ci_object_pool_register("pack_allocator_t", sizeof_pack_allocator());
    assert(PACK_ALLOCATOR_POOL >= 0);

    return ret;
}

void ci_mem_reset()
{
}

void ci_object_pools_destroy();
void ci_mem_exit()
{
    ci_mem_allocator_destroy(default_allocator);
    default_allocator = NULL;
    ci_buffers_destroy();
    MEM_ALLOCATOR_POOL = -1;
    PACK_ALLOCATOR_POOL = -1;
    ci_object_pools_destroy();
}

void ci_mem_allocator_destroy(ci_mem_allocator_t *allocator)
{
    /* The allocator->destroy may release allocator struct */
    int must_free = allocator->must_free;
    void (*destroyer)(struct ci_mem_allocator *);
    destroyer = allocator->destroy;

    destroyer(allocator);
    /*space for ci_mem_allocator_t struct is not always allocated
      using malloc */
    if (must_free == 1)
        free(allocator);
    else if (must_free == 2)
        ci_object_pool_free(allocator);
/*
    else if (allocator->must_free == 0) {
        user is responsible to release the allocator object
        or the object is already released while the
        destroyer/allocator->destroy is called.
    }
*/

}

/******************/
static ci_mem_allocator_t *alloc_mem_allocator_struct()
{
    ci_mem_allocator_t *alc;
    if (MEM_ALLOCATOR_POOL < 0) {
        alc = (ci_mem_allocator_t *) malloc(sizeof(ci_mem_allocator_t));
        alc->must_free = 1;
    } else {
        alc = (ci_mem_allocator_t *) ci_object_pool_alloc(MEM_ALLOCATOR_POOL);
        alc->must_free = 2;
    }
    alc->stats.os_malloc = 0;
    alc->stats.os_free = 0;
    alc->stats.pool_alloc = 0;
    alc->stats.idle = 0;
    return alc;
}

/*******************************************************************/
/* Buffers pool api functions                                      */
#define BUF_SIGNATURE 0xAA55
struct mem_buffer_block {
    uint16_t sig;
    size_t ID;
    union {
        double __align;
        char ptr[1];
    } data;
};

#if !defined(offsetof)
#define offsetof(type,member) ((size_t) &((type*)0)->member)
#endif
#define PTR_OFFSET offsetof(struct mem_buffer_block,data.ptr[0])

static ci_mem_allocator_t *short_buffers[16];
int short_buffers_length = sizeof(short_buffers)/sizeof(ci_mem_allocator_t *);
static ci_mem_allocator_t *long_buffers[32];
int long_buffers_length = sizeof(long_buffers)/sizeof(ci_mem_allocator_t *);


enum {
    BUF64_POOL, BUF128_POOL, BUF256_POOL,BUF512_POOL, BUF1024_POOL,
    BUF2048_POOL, BUF4096_POOL, BUF8192_POOL, BUF16384_POOL, BUF32768_POOL,
    BUF65536_POOL, BUF_END_POOL
};

static ci_mem_allocator_t *Pools[BUF_END_POOL];

int ci_buffers_init()
{
    int i;
    memset(Pools, 0, sizeof(Pools));
    memset(short_buffers, 0, sizeof(short_buffers));
    memset(long_buffers, 0, sizeof(long_buffers));

    Pools[BUF64_POOL] = ci_create_pool_allocator("64bytes", 64+PTR_OFFSET);
    Pools[BUF128_POOL] = ci_create_pool_allocator("128bytes", 128+PTR_OFFSET);
    Pools[BUF256_POOL] = ci_create_pool_allocator("256bytes", 256+PTR_OFFSET);
    Pools[BUF512_POOL] = ci_create_pool_allocator("512bytes", 512+PTR_OFFSET);
    Pools[BUF1024_POOL] = ci_create_pool_allocator("1Kb", 1024+PTR_OFFSET);

    Pools[BUF2048_POOL] = ci_create_pool_allocator("2Kb", 2048+PTR_OFFSET);
    Pools[BUF4096_POOL] = ci_create_pool_allocator("4Kb", 4096+PTR_OFFSET);
    Pools[BUF8192_POOL] = ci_create_pool_allocator("8Kb", 8192+PTR_OFFSET);
    Pools[BUF16384_POOL] = ci_create_pool_allocator("16Kb", 16384+PTR_OFFSET);
    Pools[BUF32768_POOL] = ci_create_pool_allocator("32Kb", 32768+PTR_OFFSET);
    Pools[BUF65536_POOL] = ci_create_pool_allocator("64Kb", 65536+PTR_OFFSET);

    short_buffers[0] = Pools[BUF64_POOL];
    short_buffers[1] = Pools[BUF128_POOL];
    short_buffers[2] = short_buffers[3] = Pools[BUF256_POOL];
    short_buffers[4] = short_buffers[5] =
                           short_buffers[6] = short_buffers[7] = Pools[BUF512_POOL];
    for (i = 8; i < 16; i++)
        short_buffers[i] = Pools[BUF1024_POOL];

    long_buffers[0] = Pools[BUF2048_POOL];
    long_buffers[1] = Pools[BUF4096_POOL];
    long_buffers[2] = long_buffers[3] = Pools[BUF8192_POOL];
    long_buffers[4] = long_buffers[5] =
                          long_buffers[6] = long_buffers[7] = Pools[BUF16384_POOL];
    for (i = 8; i < 16; i++)
        long_buffers[i] = Pools[BUF32768_POOL];
    for(i = 16; i < 32; i++)
        long_buffers[i] = Pools[BUF65536_POOL];
    return 1;
}

static int short_buffer_sizes[16] =  {
    64,
    128,
    256,256,
    512, 512, 512, 512,
    1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024
};

static int long_buffer_sizes[32] =  {
    2048,
    4096,
    8192, 8192,
    16384, 16384, 16384, 16384,
    32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768,
    65536, 65536, 65536, 65536, 65536, 65536, 65536, 65536,
    65536, 65536, 65536, 65536, 65536, 65536, 65536, 65536
};

void ci_buffers_destroy()
{
    int i;
    for (i = 0; i < BUF_END_POOL; i++) {
        if (Pools[i] != NULL)
            ci_mem_allocator_destroy(Pools[i]);
    }
    memset(Pools, 0, sizeof(Pools));
    memset(short_buffers, 0, sizeof(short_buffers));
    memset(long_buffers, 0, sizeof(long_buffers));
}

void *ci_buffer_alloc2(size_t block_size, size_t *allocated_size)
{
    int type;
    size_t mem_size, allocated_buffer_size;
    struct mem_buffer_block *block = NULL;
    if (block_size == 0)
        return nullptr;
    mem_size = block_size + PTR_OFFSET;
    type = (block_size-1) >> 6;
    if (type < 16) {
        assert(short_buffers[type] != NULL);
        block = (struct mem_buffer_block *) short_buffers[type]->alloc(short_buffers[type], mem_size);
        allocated_buffer_size = short_buffer_sizes[type];
    } else if (type < 1024) {
        int long_sub_type = type >> 5;
        assert(long_sub_type < long_buffers_length);
        assert(long_buffers[long_sub_type] != NULL);
        block = (struct mem_buffer_block *) long_buffers[long_sub_type]->alloc(long_buffers[long_sub_type], mem_size);
        allocated_buffer_size = long_buffer_sizes[long_sub_type];
        assert(long_sub_type <= 15);
    } else {
        block = (struct mem_buffer_block *) malloc(mem_size);
        allocated_buffer_size = block_size;
    }

    if (!block) {
        DEBUG(0, "Failed to allocate space for buffer of size: " << (int)block_size);
        return NULL;
    }

    block->sig = BUF_SIGNATURE;
    if (allocated_size) {
        *allocated_size = allocated_buffer_size;
        block->ID = allocated_buffer_size;
    } else
        block->ID = block_size;
    DEBUG(9, "Requested size " << (int)block_size << ", getting buffer " << (void *)block->data.ptr << " from pool " << type << ":" << (int)allocated_buffer_size);
    return (void *)block->data.ptr;
}

void *ci_buffer_alloc(size_t block_size)
{
    return ci_buffer_alloc2(block_size, NULL);
}

static struct mem_buffer_block *to_block(const void *data)
{
    struct mem_buffer_block *block;
    block = (struct mem_buffer_block *)(((char *)data) - PTR_OFFSET);
    if (block->sig != BUF_SIGNATURE) {
        DEBUG(0,"ci_buffer internal check: ERROR, " << data << " is not a ci_buffer object. This is a bug!!!!");
        return NULL;
    }
    return block;
}

CI_DECLARE_FUNC(int)  ci_buffer_check(const void *data)
{
    return to_block(data) ? 1 : 0;
}

CI_DECLARE_FUNC(size_t)  ci_buffer_size(const void *data)
{
    const struct mem_buffer_block *block = to_block(data);
    return block ? block->ID : 0;
}

size_t ci_buffer_real_size(const void *data)
{
    const struct mem_buffer_block *block = to_block(data);
    if (!block)
        return 0;

    int type;
    size_t buffer_block_size = 0;
    type = (block->ID - 1) >> 6;
    if (type < 16) {
        assert(short_buffers[type] != NULL);
        buffer_block_size = short_buffer_sizes[type];
    } else if (type < 1024) {
        type = type >> 5;
        assert(type < long_buffers_length);
        assert(long_buffers[type] != NULL);
        buffer_block_size = long_buffer_sizes[type];
    } else
        buffer_block_size = block->ID;
    return buffer_block_size;
}

void *  ci_buffer_realloc_xxx(const void *old_data, size_t new_block_size, size_t *old_size, size_t *allocated_size)
{
    if (!old_data) {
        if (old_size)
            *old_size = 0;
        return ci_buffer_alloc2(new_block_size, allocated_size);
    }

    size_t current_buffer_size = 0;
    struct mem_buffer_block *old_block;

    if (!(old_block = to_block(old_data))) {
        return NULL;
    }

    current_buffer_size = ci_buffer_real_size(old_data);
    assert(current_buffer_size > 0);
    DEBUG(9, "Current buffer " << old_data << " of size for realloc: " << current_buffer_size << ", [requested block size]/[current size]: " <<
          new_block_size << "/" << (int)old_block->ID);
    if (old_size)
        *old_size = current_buffer_size;
    void *new_data = nullptr;
    /*If no block_size created than our buffer actual size probably requires a realloc.....*/
    if (new_block_size > current_buffer_size) {
        new_data = ci_buffer_alloc2(new_block_size, allocated_size);
        if (!new_data)
            return NULL;
        memcpy(new_data, old_block->data.ptr, old_block->ID);
        ci_buffer_free(old_block->data.ptr);
        old_block = nullptr;
    } else {
        new_data = old_block->data.ptr;
        /*we neeed to update block->ID to the new requested size...*/
        if (allocated_size) {
            *allocated_size = current_buffer_size;
            old_block->ID = current_buffer_size;
        } else {
            old_block->ID = new_block_size;
        }
    }

    DEBUG(9, "New memory buffer " << new_data << " , [requested block size]/[retrieved size]:" <<  (int) new_block_size << "/" << (int)ci_buffer_real_size(new_data));

    return new_data;
}

void * ci_buffer_realloc(const void *data, size_t block_size)
{
    return ci_buffer_realloc_xxx(data, block_size, NULL, NULL);
}

void * ci_buffer_realloc2(const void *data, size_t block_size, size_t *allocated_size)
{
    return ci_buffer_realloc_xxx(data, block_size, NULL, allocated_size);
}

void * ci_buffer_realloc3(const void *data, size_t block_size, size_t *old_size)
{
    return ci_buffer_realloc_xxx(data, block_size,  old_size, NULL);
}

void *pool_allocator_mem_to_raw(void *p);
void ci_buffer_free2(void *data, size_t *return_block_size)
{
    int type;
    size_t block_size;
    struct mem_buffer_block *block;

    if (!data)
        return;

    if (!(block = to_block(data)))
        return;

    block_size = block->ID;
    type = (block_size-1) >> 6;
    if (return_block_size)
        *return_block_size = block_size;
    if (SHUTDOWN && type < 512) {
        free(pool_allocator_mem_to_raw(block));
        return;
    }
    if (type < 16) {
        assert(short_buffers[type] != NULL);
        short_buffers[type]->free(short_buffers[type], block);
        DEBUG(9, "Store buffer " << data << " (used " << (int)block_size << " bytes) to short pool " << type << ":" << short_buffer_sizes[type]);
    } else if (type < 1024) {
        int long_sub_type = type >> 5;
        assert(long_sub_type < long_buffers_length);
        assert(long_buffers[long_sub_type] != NULL);
        long_buffers[long_sub_type]->free(long_buffers[long_sub_type], block);
        DEBUG(9, "Store buffer " << data << " (used " << (int)block_size << " bytes) to short pool " << type << ":" << long_buffer_sizes[long_sub_type]);
    } else {
        DEBUG(9, "Free buffer " << data <<" (free at " << block << ", used bytes: " << (int)block->ID);
        free(block);
    }
}

void ci_buffer_free(void *data)
{
    ci_buffer_free2(data, NULL);
}

void ci_buffer_dump_stats()
{
    uint64_t mem_sum = 0, mem_sum_with_xdata = 0;
    const size_t metadata_size = PTR_OFFSET + pool_allocator_objects_metadata_size();
    DEBUG(1, "Buffers_Pool ,  malloc ,  free ,  pool_alloc , idle");
    // TODO: Write to an std::ostringstream and print them as one write.
    for (int i = 0; i < BUF_END_POOL; ++i) {
        if (Pools[i]) {
            ci_mem_allocator *m = Pools[i];
            DEBUG(1, "pool " << m->name << " , " <<  m->stats.os_malloc << " , " << m->stats.os_free << " , "  << m->stats.pool_alloc << " , " << m->stats.idle);
            size_t objSize = pool_allocator_objects_size(m) - PTR_OFFSET;
            mem_sum += objSize * m->stats.os_malloc;
            mem_sum_with_xdata += (objSize + metadata_size) * m->stats.os_malloc;
        }
    }
    DEBUG(1, "Buffers allocated memory size = " << mem_sum << ",  Memory size with metadata = " << mem_sum_with_xdata);
}

/*******************************************************************/
/*A simple allocator implementation which uses the system malloc    */

static void *os_allocator_alloc(ci_mem_allocator_t *allocator,size_t size)
{
    return malloc(size);
}

static void os_allocator_free(ci_mem_allocator_t *allocator,void *p)
{
    free(p);
}

static void os_allocator_reset(ci_mem_allocator_t *allocator)
{
    /*nothing to do*/
}

static void os_allocator_destroy(ci_mem_allocator_t *allocator)
{
    /*nothing to do*/
}

ci_mem_allocator_t *ci_create_os_allocator()
{
    ci_mem_allocator_t *allocator = alloc_mem_allocator_struct();
    if (!allocator)
        return NULL;
    allocator->alloc = os_allocator_alloc;
    allocator->free = os_allocator_free;
    allocator->reset = os_allocator_reset;
    allocator->destroy = os_allocator_destroy;
    allocator->data = NULL;
    allocator->name = NULL;
    allocator->type = OS_ALLOC;
    return allocator;
}

/*Static declaration of an os allocator*/
ci_mem_allocator_t os_allocator_local = {
    os_allocator_alloc,
    os_allocator_free,
    os_allocator_reset,
    os_allocator_destroy,
    NULL,
    "ci_os_allocator",
    OS_ALLOC,
    0 /*must_free*/
};

/*
  The ci_mem_allocator objects can not be const, because their operations
  may modify their self.
  TODO: check how they can be const
*/
ci_mem_allocator_t *ci_os_allocator = &os_allocator_local;

/************************************************************/
/* The serial allocator implementation                      */
typedef struct serial_allocator {
    char *memchunk;
    char *curpos;
    char *endpos;
    struct serial_allocator *next;
} serial_allocator_t;


static serial_allocator_t *serial_allocator_build(size_t size)
{
    serial_allocator_t *serial_alloc;
    char *buffer;
    size = _CI_ALIGN(size);
    /*The serial_allocator and mem_allocator structures will be
     allocated in the buffer */
    if (size < sizeof(serial_allocator_t) + sizeof(ci_mem_allocator_t))
        return NULL;

    /*The allocated block size maybe is larger, than the requested.
      Fix size to actual block size */
    buffer = (char *)ci_buffer_alloc2(size, &size);
    serial_alloc = (serial_allocator_t *)buffer;

    serial_alloc->memchunk = buffer + sizeof(serial_allocator_t);
    size -= sizeof(serial_allocator_t);
    serial_alloc->curpos = serial_alloc->memchunk;
    serial_alloc->endpos = serial_alloc->memchunk + size;
    serial_alloc->next = NULL;
    return serial_alloc;
}

static void *serial_allocation(serial_allocator_t *serial_alloc, size_t size)
{
    size_t max_size;
    char *mem;
    size = _CI_ALIGN(size); /*round size to a correct alignment size*/
    max_size = serial_alloc->endpos - serial_alloc->memchunk;
    if (size > max_size)
        return NULL;

    while (size > (size_t)(serial_alloc->endpos - serial_alloc->curpos)) {
        if (serial_alloc->next == NULL) {
            serial_alloc->next = serial_allocator_build(max_size);
            if (!serial_alloc->next)
                return NULL;
        }
        serial_alloc = serial_alloc->next;
    }

    mem = serial_alloc->curpos;
    serial_alloc->curpos += size;
    return (void *)mem;
}

static void *serial_allocator_alloc(ci_mem_allocator_t *allocator,size_t size)
{
    serial_allocator_t *serial_alloc = (serial_allocator_t *)allocator->data;

    if (!serial_alloc)
        return NULL;
    return serial_allocation(serial_alloc, size);
}

static void serial_allocator_free(ci_mem_allocator_t *allocator,void *p)
{
    /* We can not free :-)  */
}

static void serial_allocator_reset(ci_mem_allocator_t *allocator)
{
    serial_allocator_t *serial_alloc, *sa;
    void *tmp;
    serial_alloc = (serial_allocator_t *)allocator->data;
    serial_alloc->curpos = serial_alloc->memchunk + _CI_ALIGN(sizeof(ci_mem_allocator_t));
    sa = serial_alloc->next;
    serial_alloc->next = NULL;

    /*release any other allocated chunk*/
    while (sa) {
        tmp = (void *)sa;
        ci_buffer_free(tmp);
        sa = sa->next;
    }
}

static void serial_allocator_destroy(ci_mem_allocator_t *allocator)
{
    serial_allocator_t *cur, *next;

    if (!allocator->data)
        return;

    cur = (serial_allocator_t *)allocator->data;
    next = cur->next;
    while (cur) {
        ci_buffer_free((void *)cur);
        cur = next;
        if (next)
            next = next->next;
    }
}

ci_mem_allocator_t *ci_create_serial_allocator(size_t size)
{
    ci_mem_allocator_t *allocator;

    serial_allocator_t *sdata= serial_allocator_build(size);

    /*Allocate space for ci_mem_allocator_t from our serial allocator ...*/
    allocator = (ci_mem_allocator_t *)serial_allocation(sdata, sizeof(ci_mem_allocator_t));
    if (!allocator) {
        ci_buffer_free((void *)sdata);
        return NULL;
    }
    allocator->alloc = serial_allocator_alloc;
    allocator->free = serial_allocator_free;
    allocator->reset = serial_allocator_reset;
    allocator->destroy = serial_allocator_destroy;
    allocator->data = sdata;
    allocator->name = NULL;
    allocator->type = SERIAL_ALLOC;
    /*It is allocated in our buffer space...*/
    allocator->must_free = 0;
    return allocator;
}
/****************************************************************/


typedef struct pack_allocator {
    char *memchunk;
    char *curpos;
    char *endpos;
    char *end;
    int must_free;
} pack_allocator_t;

/*Api functions for pack allocator:*/
void *ci_pack_allocator_alloc_unaligned(ci_mem_allocator_t *allocator, size_t size)
{
    size_t max_size;
    char *mem;
    pack_allocator_t *pack_alloc;

    assert(allocator->type == PACK_ALLOC);
    pack_alloc = (pack_allocator_t *)allocator->data;

    if (!pack_alloc)
        return NULL;

    max_size = (size_t)(pack_alloc->endpos - pack_alloc->curpos);

    if (size > max_size)
        return NULL;

    mem = pack_alloc->curpos;
    pack_alloc->curpos += size;
    return (void *)mem;
}

void *ci_pack_allocator_alloc(ci_mem_allocator_t *allocator,size_t size)
{
    size = _CI_ALIGN(size); /*round size to a correct alignment size*/
    return ci_pack_allocator_alloc_unaligned(allocator, size);
}

void  *ci_pack_allocator_alloc_from_rear2(ci_mem_allocator_t *allocator, int size, int align)
{
    int max_size;
    char *mem;
    pack_allocator_t *pack_alloc;

    assert(allocator->type == PACK_ALLOC);
    pack_alloc = (pack_allocator_t *)allocator->data;

    if (!pack_alloc)
        return NULL;

    if (align)
        size = _CI_ALIGN(size); /*round size to a correct alignment size*/
    max_size = pack_alloc->endpos - pack_alloc->curpos;

    if (size > max_size)
        return NULL;

    pack_alloc->endpos -= size; /*Allocate block from the end of memory block*/
    mem = pack_alloc->endpos;
    return (void *)mem;
}

void  *ci_pack_allocator_alloc_from_rear(ci_mem_allocator_t *allocator, int size)
{
    return ci_pack_allocator_alloc_from_rear2(allocator, size, 1);
}

void  *ci_pack_allocator_alloc_from_rear_unaligned(ci_mem_allocator_t *allocator, int size)
{
    return ci_pack_allocator_alloc_from_rear2(allocator, size, 0);
}

void ci_pack_allocator_free(ci_mem_allocator_t *allocator,void *p)
{
    /* We can not free :-)  */
}

void ci_pack_allocator_reset(ci_mem_allocator_t *allocator)
{
    pack_allocator_t *pack_alloc;
    assert(allocator->type == PACK_ALLOC);
    pack_alloc = (pack_allocator_t *)allocator->data;
    pack_alloc->curpos = pack_alloc->memchunk;
    pack_alloc->endpos = pack_alloc->end;
}

void ci_pack_allocator_destroy(ci_mem_allocator_t *allocator)
{
    pack_allocator_t *pack_alloc;
    assert(allocator->type == PACK_ALLOC);
    pack_alloc = (pack_allocator_t *)allocator->data;
    if (pack_alloc->must_free != 0) {
        ci_object_pool_free(allocator->data);
        allocator->data = NULL;
    }
}

/*If "off" is not aligned return the first smaller aligned offset*/
#define _ALIGNED_OFFSET(off) (off != _CI_ALIGN(off) ? _CI_ALIGN(off - _CI_NBYTES_ALIGNMENT) : off)

ci_mem_allocator_t *init_pack_allocator(ci_mem_allocator_t *allocator, pack_allocator_t *pack_alloc, char *memblock, size_t size, int free)
{
    /*We may not be able to use all of the memblock size.
      We need to support allocating memory space from the end, so we
      need to have aligned the pack_alloc->end to correctly calculate
      memory block offsets from the end in ci_pack_allocator_alloc_from_rear
      function.
    */
    size =  _ALIGNED_OFFSET(size);
    pack_alloc->memchunk = memblock;
    pack_alloc->curpos =pack_alloc->memchunk;
    pack_alloc->end = pack_alloc->memchunk + size;
    pack_alloc->endpos = pack_alloc->end;
    pack_alloc->must_free = free;

    allocator->alloc = ci_pack_allocator_alloc;
    allocator->free = ci_pack_allocator_free;
    allocator->reset = ci_pack_allocator_reset;
    allocator->destroy = ci_pack_allocator_destroy;
    allocator->data = pack_alloc;
    allocator->name = NULL;
    allocator->type = PACK_ALLOC;
    allocator->must_free = free;
    return allocator;
}

ci_mem_allocator_t *ci_create_pack_allocator(char *memblock, size_t size)
{
    ci_mem_allocator_t *allocator;
    pack_allocator_t *pack_alloc;
    pack_alloc = (pack_allocator_t *)ci_object_pool_alloc(PACK_ALLOCATOR_POOL);
    if (!pack_alloc)
        return NULL;
    allocator = alloc_mem_allocator_struct();
    if (!allocator) {
        ci_object_pool_free(pack_alloc);
        return NULL;
    }

    return   init_pack_allocator(allocator, pack_alloc, memblock, size, 2);
}

/*similar to the above but allocates required space for pack_allocator on the given memblock*/
ci_mem_allocator_t *ci_create_pack_allocator_on_memblock(char *memblock, size_t size)
{
    ci_mem_allocator_t *allocator;

    /*We need to allocate space on memblock for internal structures*/
    if (size <= (_CI_ALIGN(sizeof(pack_allocator_t)) + _CI_ALIGN(sizeof(ci_mem_allocator_t))))
        return NULL;

    pack_allocator_t *pack_alloc = (pack_allocator_t *)memblock;
    memblock += _CI_ALIGN(sizeof(pack_allocator_t));
    size -= _CI_ALIGN(sizeof(pack_allocator_t));
    allocator = (ci_mem_allocator_t *)memblock;
    memblock += _CI_ALIGN(sizeof(ci_mem_allocator_t));
    size -= _CI_ALIGN(sizeof(ci_mem_allocator_t));

    return   init_pack_allocator(allocator, pack_alloc, memblock, size, 0);
}

int ci_pack_allocator_data_size(ci_mem_allocator_t *allocator)
{
    assert(allocator->type == PACK_ALLOC);
    pack_allocator_t *pack_alloc = (pack_allocator_t *)allocator->data;
    return (int) (pack_alloc->curpos - pack_alloc->memchunk) +
           (pack_alloc->end - pack_alloc->endpos);
}

size_t  ci_pack_allocator_required_size()
{
    return _CI_ALIGN(sizeof(pack_allocator_t)) + _CI_ALIGN(sizeof(ci_mem_allocator_t));
}

static size_t sizeof_pack_allocator() {return sizeof(pack_allocator_t);}

void ci_pack_allocator_set_start_pos(ci_mem_allocator_t *allocator, void *p)
{
    pack_allocator_t *pack_alloc;
    assert(allocator->type == PACK_ALLOC);
    pack_alloc = (pack_allocator_t *)allocator->data;
    assert((char *)p >= pack_alloc->memchunk);
    pack_alloc->curpos = (char *)p;
}

void ci_pack_allocator_set_end_pos(ci_mem_allocator_t *allocator, void *p)
{
    pack_allocator_t *pack_alloc;
    assert(allocator->type == PACK_ALLOC);
    pack_alloc = (pack_allocator_t *)allocator->data;
    assert((char *)p <= pack_alloc->end);
    if (p == NULL)
        pack_alloc->endpos = pack_alloc->end;
    else
        pack_alloc->endpos = (char *)p;
}

/****************************************************************/

#define MEM_BLOCK_SIGNATURE 0xAAAA
struct mem_block_item {
    uint16_t sig;
    uint16_t flags;
    struct mem_block_item *next;
     union {
        double __align;
        char ptr[1];
    } data;
};

#define MEM_BLOCK_DATA_OFFSET offsetof(struct mem_block_item, data.ptr[0])

struct pool_allocator {
    char *name;
    size_t items_size;
    int strict;

    /*
    int stat_allocs_id;
    int stat_hits_id;
    int stat_idle_id;
    int stat_used_id;
    int disable_stats;
    */
    pthread_mutex_t mutex;
    struct mem_block_item *free;
};

static struct pool_allocator *pool_allocator_build(const char *name, size_t items_size, int strict)
{
    struct pool_allocator *palloc;

    palloc = (struct pool_allocator *)malloc(sizeof(struct pool_allocator));

    if (!palloc) {
        return NULL;
    }

    palloc->name = name ? strdup(name) : NULL;
    palloc->items_size = items_size;
    palloc->strict = strict;
    palloc->free = NULL;

    pthread_mutex_init(&palloc->mutex, nullptr);
    return palloc;
}

static void *pool_allocator_alloc(ci_mem_allocator_t *allocator,size_t size)
{
    struct mem_block_item *mem_item;
    struct pool_allocator *palloc = (struct pool_allocator *)allocator->data;

    if (size > (size_t)palloc->items_size)
        return NULL;

    pthread_mutex_lock(&palloc->mutex);
    if (palloc->free) {
        mem_item = palloc->free;
        palloc->free=palloc->free->next;
        allocator->stats.pool_alloc++;
        allocator->stats.idle--;
    } else {
        mem_item = (struct mem_block_item *)malloc(palloc->items_size + MEM_BLOCK_DATA_OFFSET);
        mem_item->sig = MEM_BLOCK_SIGNATURE;
        mem_item->flags = 0;
        mem_item->next = NULL;
        allocator->stats.os_malloc++;
    }

    pthread_mutex_unlock(&palloc->mutex);
    return (void *)mem_item->data.ptr;
}

void *pool_allocator_mem_to_raw(void *p)
{
    return (char *)p - MEM_BLOCK_DATA_OFFSET;
}

static void pool_allocator_free(ci_mem_allocator_t *allocator,void *p)
{
    struct mem_block_item *mem_item;
    struct pool_allocator *palloc = (struct pool_allocator *)allocator->data;

    mem_item = (struct mem_block_item *)pool_allocator_mem_to_raw(p);
    if (ZeroMemBeforeRelease) {
        memset(mem_item->data.ptr, 0, palloc->items_size);
    }
    pthread_mutex_lock(&palloc->mutex);
    if (CheckDuplicateFrees) {
        for (struct mem_block_item *mp = palloc->free; mp != nullptr; mp=mp->next) {
            if (mp == mem_item) {
                DEBUG(0, "Releases an already released object in pool " << palloc->name);
                assert(!(std::string("duplicate free pool ").append(palloc->name)).c_str());
            }
        }
    }
    mem_item->next = palloc->free;
    palloc->free = mem_item;
    allocator->stats.idle++;
    pthread_mutex_unlock(&palloc->mutex);
}

static void pool_allocator_reset(ci_mem_allocator_t *allocator)
{
    struct mem_block_item *mem_item, *cur;
    struct pool_allocator *palloc = (struct pool_allocator *)allocator->data;
    pthread_mutex_lock(&palloc->mutex);
    if (palloc->free) {
        int freed = 0;
        mem_item = palloc->free;
        while (mem_item != NULL) {
            cur = mem_item;
            mem_item = mem_item->next;
            free(cur);
            freed++;
        }
        allocator->stats.os_free += freed;
        allocator->stats.idle -= freed;
    }
    palloc->free = NULL;
    pthread_mutex_unlock(&palloc->mutex);
}


static void pool_allocator_destroy(ci_mem_allocator_t *allocator)
{
    pool_allocator_reset(allocator);
    struct pool_allocator *palloc = (struct pool_allocator *)allocator->data;
    pthread_mutex_destroy(&palloc->mutex);
    free(palloc->name);
    free(palloc);
}

size_t  pool_allocator_objects_size(const ci_mem_allocator_t *allocator)
{
    assert(allocator->type == POOL_ALLOC);
    const struct pool_allocator *palloc =  (const struct pool_allocator *)allocator->data;
    return palloc->items_size;
}

size_t  pool_allocator_objects_metadata_size()
{
    return (MEM_BLOCK_DATA_OFFSET);
}

ci_mem_allocator_t *ci_create_pool_allocator(const char *name, size_t items_size)
{
    struct pool_allocator *palloc;
    ci_mem_allocator_t *allocator;

    palloc = pool_allocator_build(name, items_size, 0);
    /*Use always malloc for ci_mem_alocator struct.*/
    allocator = (ci_mem_allocator_t *) malloc(sizeof(ci_mem_allocator_t));
    if (!allocator)
        return NULL;
    allocator->alloc = pool_allocator_alloc;
    allocator->free = pool_allocator_free;
    allocator->reset = pool_allocator_reset;
    allocator->destroy = pool_allocator_destroy;
    allocator->data = palloc;
    allocator->name = name ? strdup(name) : NULL;
    allocator->type = POOL_ALLOC;
    allocator->must_free = 1;
    allocator->stats.os_malloc = 0;
    allocator->stats.os_free = 0;
    allocator->stats.pool_alloc = 0;
    allocator->stats.idle = 0;
    return allocator;
}

/*******************************************************************/
/*Object pools                                                     */
#define OBJ_SIGNATURE 0x55AA
ci_mem_allocator_t **object_pools = NULL;
unsigned long object_pools_size = 0;
unsigned long object_pools_used = 0;

int ci_object_pools_init()
{
    return 1;
}

void ci_object_pools_destroy()
{
    unsigned int i;
    for (i = 0; i < object_pools_used; i++) {
        if (object_pools[i] != NULL)
            ci_mem_allocator_destroy(object_pools[i]);
    }
}

#define STEP 128
int ci_object_pool_register(const char *name, size_t size)
{
    int ID, i;
    ID = -1;
    /*search for an empty position on object_pools and assign here?*/
    if (object_pools == NULL) {
        object_pools = (ci_mem_allocator_t**) malloc(STEP*sizeof(ci_mem_allocator_t *));
        object_pools_size = STEP;
        ID = 0;
    } else {
        for (i = 0; i < (int)object_pools_used; i++)  {
            if (object_pools[i] == NULL) {
                ID = i;
                break;
            }
        }
        if (ID == -1) {
            if (object_pools_size == object_pools_used) {
                object_pools_size += STEP;
                object_pools = (ci_mem_allocator_t**) realloc(object_pools, object_pools_size*sizeof(ci_mem_allocator_t *));
            }
            ID=object_pools_used;
        }
    }
    if (object_pools == NULL) //??????
        return -1;

    object_pools[ID] = ci_create_pool_allocator(name, size+PTR_OFFSET);

    object_pools_used++;
    return ID;
}

void ci_object_pool_unregister(int id)
{
    if (id >= (int)object_pools_used || id < 0) {
        /*A error message ....*/
        return;
    }
    if (object_pools[id]) {
        ci_mem_allocator_destroy(object_pools[id]);
        object_pools[id] = NULL;
    }

}

void *ci_object_pool_alloc(int id)
{
    struct mem_buffer_block *block = NULL;
    if (id >= (int)object_pools_used || id < 0 || !object_pools[id]) {
        /*A error message ....*/
        DEBUG(0, "Invalid object pool " << id <<". This is a BUG!");
        return NULL;
    }
    block = (struct mem_buffer_block *) object_pools[id]->alloc(object_pools[id], 1/*A small size smaller than obj size*/);
    if (!block) {
        DEBUG(1, "Failed to allocate object from pool " << id);
        return NULL;
    }
    DEBUG(8, "Allocating from objects pool object " << id);
    block->sig = OBJ_SIGNATURE;
    block->ID = id;
    return (void *)block->data.ptr;
}

void ci_object_pool_free(void *ptr)
{
    struct mem_buffer_block *block = (struct mem_buffer_block *)((char *)ptr - PTR_OFFSET);
    if (block->sig != OBJ_SIGNATURE) {
        DEBUG(0,"ci_object_pool_free: ERROR, " << ptr << " is not internal buffer. This is a bug!!!!");
        return;
    }
    if ((unsigned long)block->ID > object_pools_used || !object_pools[block->ID]) {
        DEBUG(0,"ci_object_pool_free: ERROR, " << ptr << " is pointing to corrupted mem? This is a bug!!!!");
        return;
    }
    DEBUG(8, "Storing to objects pool object " << (int)block->ID);
    object_pools[block->ID]->free(object_pools[block->ID], block);
}

size_t  ci_object_pool_objects_size(int id)
{
    if (id >= (int)object_pools_used || id < 0 || !object_pools[id]) {
        DEBUG(0, "Invalid object pool " << id <<". This is a BUG!");
        return 0;
    }
    return pool_allocator_objects_size(object_pools[id]) - PTR_OFFSET;
}

size_t  ci_object_pool_objects_metadata_size()
{
    return (PTR_OFFSET + pool_allocator_objects_metadata_size());
}

void ci_object_pools_dump_stats()
{
    // TODO: Write to an std::ostringstream and print them as one write.
    uint64_t mem_sum = 0, mem_sum_with_xdata = 0;
    const size_t metadata_size = ci_object_pool_objects_metadata_size();
    DEBUG(1, "Objects_Pool ,  object_size , malloc ,  free ,  pool_alloc , idle");
    for (unsigned int i = 0; i < object_pools_used; i++) {
        if (object_pools[i] != NULL) {
            ci_mem_allocator *m = object_pools[i];
            size_t objSize = ci_object_pool_objects_size(i);
            DEBUG(1, "pool " << m->name << " , " << objSize << " , " <<  m->stats.os_malloc << " , " << m->stats.os_free << " , "  << m->stats.pool_alloc << " , " << m->stats.idle);
            mem_sum += objSize * m->stats.os_malloc;
            mem_sum_with_xdata += (objSize + metadata_size) * m->stats.os_malloc;
        }
    }
    DEBUG(1, "Objects allocated memory size = " << mem_sum << ",  Memory size with metadata = " << mem_sum_with_xdata);
}

ci_buffers_histo::ci_buffers_histo(const char *n): name(n)
{
    histo = new Bin[BUF_END_POOL + 1];
    for (int i = 0; i < BUF_END_POOL; i++) {
        histo[i].value = std::pow(2, i + 6);
    }
    histo[BUF_END_POOL].value = -1;
}

void ci_buffers_histo::updateAlloc(int size)
{
    for (int i = 0; i < BUF_END_POOL; i++) {
        if (size <= histo[i].value) {
            histo[i].allocs++;
            return;
        }
    }
    histo[BUF_END_POOL].allocs++;
}

void ci_buffers_histo::updateFree(int size) {
    for (int i = 0; i < BUF_END_POOL; i++) {
        if (size <= histo[i].value) {
            histo[i].frees++;
            return;
        }
    }
    histo[BUF_END_POOL].frees++;
}

void ci_buffers_histo::dump()
{
    std::stringstream ss;
    for (int i = 0; i < BUF_END_POOL; i++) {
        ss << histo[i].value << ":" << histo[i].allocs << "/" << histo[i].frees <<" ";
    }
    ss << "Larger:" <<histo[BUF_END_POOL].allocs << "/" << histo[BUF_END_POOL].frees;
    DEBUG(1, "ci_buffers_histo: " << name << "(block::allocs/frees): [" << ss.str() << "]");
}

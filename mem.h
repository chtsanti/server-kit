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

#ifndef __C_ICAP_MEM_H
#define __C_ICAP_MEM_H

#include <atomic>
#include <cassert>

#define CI_DECLARE_FUNC(type)  type
#define CI_DECLARE_DATA

enum allocator_types {OS_ALLOC, SERIAL_ALLOC, POOL_ALLOC, PACK_ALLOC};

typedef struct ci_mem_allocator {
    void *(*alloc)(struct ci_mem_allocator *,size_t size);
    void (*free)(struct ci_mem_allocator *,void *);
    void (*reset)(struct ci_mem_allocator *);
    void (*destroy)(struct ci_mem_allocator *);
    void *data;
    const char *name;
    int type;
    int must_free;
    struct {
        uint64_t os_malloc;
        uint64_t os_free;
        uint64_t pool_alloc;
        uint64_t idle;
    } stats;
} ci_mem_allocator_t;

CI_DECLARE_DATA extern ci_mem_allocator_t *ci_os_allocator;
CI_DECLARE_DATA extern ci_mem_allocator_t *default_allocator; /* Deprecated */
extern bool ZeroMemBeforeRelease;
extern bool CheckDuplicateFrees;

CI_DECLARE_FUNC(void) ci_mem_allocator_destroy(ci_mem_allocator_t *allocator);
CI_DECLARE_FUNC(ci_mem_allocator_t *) ci_create_os_allocator();
CI_DECLARE_FUNC(ci_mem_allocator_t *) ci_create_serial_allocator(size_t size);

/*pack_allocator related functions ....*/
CI_DECLARE_FUNC(ci_mem_allocator_t *) ci_create_pack_allocator(char *memblock, size_t  size);
CI_DECLARE_FUNC(int) ci_pack_allocator_data_size(ci_mem_allocator_t *allocator);
CI_DECLARE_FUNC(void *) ci_pack_allocator_alloc(ci_mem_allocator_t *allocator,size_t size);
CI_DECLARE_FUNC(void) ci_pack_allocator_free(ci_mem_allocator_t *allocator,void *p);
/*The following six functions are only for c-icap internal use....*/
CI_DECLARE_FUNC(ci_mem_allocator_t *)ci_create_pack_allocator_on_memblock(char *memblock, size_t size);
CI_DECLARE_FUNC(size_t)  ci_pack_allocator_required_size();
CI_DECLARE_FUNC(void *) ci_pack_allocator_alloc_unaligned(ci_mem_allocator_t *allocator, size_t size);
CI_DECLARE_FUNC(void *) ci_pack_allocator_alloc_from_rear2(ci_mem_allocator_t *allocator, int size, int align);
CI_DECLARE_FUNC(void *) ci_pack_allocator_alloc_from_rear(ci_mem_allocator_t *allocator, int size);
CI_DECLARE_FUNC(void *) ci_pack_allocator_alloc_from_rear_unaligned(ci_mem_allocator_t *allocator, int size);
CI_DECLARE_FUNC(void) ci_pack_allocator_set_start_pos(ci_mem_allocator_t *allocator, void *p);
CI_DECLARE_FUNC(void) ci_pack_allocator_set_end_pos(ci_mem_allocator_t *allocator, void *p);

CI_DECLARE_FUNC(int) ci_buffers_init();
CI_DECLARE_FUNC(void) ci_buffers_destroy();

CI_DECLARE_FUNC(void *)  ci_buffer_alloc(size_t block_size);
CI_DECLARE_FUNC(void *)  ci_buffer_alloc2(size_t block_size, size_t *allocated_size);
CI_DECLARE_FUNC(void *)  ci_buffer_realloc(const void *data, size_t block_size);
CI_DECLARE_FUNC(void *)  ci_buffer_realloc2(const void *data, size_t block_size, size_t *allocated_size);
CI_DECLARE_FUNC(void *)  ci_buffer_realloc3(const void *data, size_t block_size, size_t *old_size);
CI_DECLARE_FUNC(void)    ci_buffer_free(void *data);
CI_DECLARE_FUNC(void)    ci_buffer_free2(void *data, size_t *block_size);

CI_DECLARE_FUNC(size_t)  ci_buffer_size(const void *data);
CI_DECLARE_FUNC(size_t) ci_buffer_real_size(const void *data);
CI_DECLARE_FUNC(int)  ci_buffer_check(const void *data);
void ci_buffer_dump_stats();

CI_DECLARE_FUNC(int)     ci_object_pool_register(const char *name, size_t size);
CI_DECLARE_FUNC(void)    ci_object_pool_unregister(int id);
CI_DECLARE_FUNC(void *)  ci_object_pool_alloc(int id);
CI_DECLARE_FUNC(void)    ci_object_pool_free(void *ptr);
CI_DECLARE_FUNC(size_t)    ci_object_pool_objects_size(int id);
CI_DECLARE_FUNC(size_t)    ci_object_pool_objects_metadata_size();
void ci_object_pools_dump_stats();

CI_DECLARE_FUNC(int) ci_mem_init();
CI_DECLARE_FUNC(void) ci_mem_exit();

template <class T>
class MemPool {
public:
    MemPool(const char *name) {
        assert (ID < 0);
        ObjSize = sizeof(T);
        ID = ci_object_pool_register(name, ObjSize);
    }
    static int ID;
    static size_t ObjSize;
};
template <class T> int MemPool<T>::ID = -1;
template <class T> size_t MemPool<T>::ObjSize = 0;


#define MEMPOOL_DECLARE(OBJ)                    \
    void* operator new(size_t size);            \
    void operator delete(void*);

#define MEMPOOL_IMPLEMENT_COMMON(OBJ, FUNC_SPECIFIER)          \
    FUNC_SPECIFIER void* OBJ::operator new(size_t size)         \
    {                                                           \
    void *obj = nullptr;                                        \
    if (MemPool<OBJ>::ID >= 0) {                                \
        assert(size <= MemPool<OBJ>::ObjSize);                  \
        obj = ci_object_pool_alloc(MemPool<OBJ>::ID);           \
        memset(obj, 0, size);                                   \
    } else {                                                    \
        obj = calloc(1, size);                                          \
      }                                                                 \
      if (!obj)                                                         \
          throw std::runtime_error("Error allocation memory for " #OBJ " object"); \
      return obj;                                                       \
      }                                                                 \
    FUNC_SPECIFIER void OBJ::operator delete(void *p)                                  \
       {                                                                \
           if (!p)                                                      \
               return;                                                  \
           if (MemPool<OBJ>::ID >= 0) {                                 \
               ci_object_pool_free(p);                                  \
           } else {                                                     \
               free(p);                                                 \
           }                                                            \
       }


#define MEMPOOL_IMPLEMENT(OBJ)                  \
    MemPool<OBJ> MEMPOOL_##OBJ(#OBJ);           \
    MEMPOOL_IMPLEMENT_COMMON(OBJ, )

#define MEMPOOL_IMPLEMENT2(SPACE, OBJ)                          \
    MemPool<SPACE::OBJ> MEMPOOL_##SPACE_##OBJ(#SPACE "::" #OBJ);      \
    MEMPOOL_IMPLEMENT_COMMON(SPACE::OBJ, )

#define MEMPOOL_IMPLEMENT_TMPL(OBJ_TMPL, CLASS )      \
    MemPool<OBJ_TMPL<CLASS> > MEMPOOL_##OBJ_TMPL_CLASS(#OBJ_TMPL"<" #CLASS ">"); \
    MEMPOOL_IMPLEMENT_COMMON(OBJ_TMPL<CLASS>, template<>)

class ci_buffers_histo {
public:
    ci_buffers_histo(const char *n);
    void updateAlloc(int size);
    void updateFree(int size);
    void dump();

public:
    std::string name;
    class Bin {
    public:
        int value;
        std::atomic<uint64_t> allocs;
        std::atomic<uint64_t> frees;
        Bin(): allocs(0), frees(0) {}
    };
    Bin *histo;
};

#endif

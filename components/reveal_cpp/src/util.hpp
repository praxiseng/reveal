#ifndef __UTIL_H__
#define __UTIL_H__


#include <cstdint>
#include <vector>
#include <tuple>
#include <string.h>
#include "md5.h"

#define maxval(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

#define minval(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b;       \
})


#define SECTOR_HASH_BYTES 16
#define FILE_HASH_BYTES 16

std::vector<uint8_t> read_file_contents(const char* path);


template <typename T>
std::vector<uint8_t> 
struct_to_byte_vector(T buf, size_t array_size=1) {
    auto ptr = reinterpret_cast<uint8_t*>(&buf);
    auto buffer = std::vector<uint8_t>(ptr, ptr+(sizeof(buf)*array_size));
    return buffer;
}


typedef struct sector_hash {
    uint8_t hash[SECTOR_HASH_BYTES] = {0};

    bool operator==(const sector_hash &other) {
        return 0==memcmp(this->hash, other.hash, sizeof(sector_hash));
    }

    bool operator!=(const sector_hash &other) {
        return 0!=memcmp(this->hash, other.hash, sizeof(sector_hash));
    }

    std::vector<uint8_t>
    get_bytes() {
        auto vec = struct_to_byte_vector(*this);
        return vec;
    }
} sector_hash_t;


typedef struct {
    uint8_t hash[FILE_HASH_BYTES] = {};
} file_hash_t;


template <typename T> 
void 
sector_hash(T* buf, size_t length, sector_hash_t & hash_out) {
    uint8_t hash[16];
    md5Bytes((const char*)buf, length, hash);
    memcpy(hash_out.hash, hash, SECTOR_HASH_BYTES);
}


template <typename T> 
void 
file_hash(T* buf, size_t length, file_hash_t & hash_out) {
    uint8_t hash[16];
    md5Bytes((const char*)buf, length, hash);
    memcpy(hash_out.hash, hash, FILE_HASH_BYTES);
}




template<typename containerT>
struct container_generator {
    using iter_t = typename containerT::iterator;
    using value_t = typename containerT::value_type;

    iter_t current;
    iter_t end;

    container_generator(containerT container) {
        current = container.begin();
        end = container.end();
    }

    value_t
    operator()() {
        return *current++;
    }

    operator bool() const {
        return current != end;
    }

};


template<typename ContainerT, typename keyT>
struct grouper {
    using value_t = typename ContainerT::value_type;
    using iter_t = typename ContainerT::iterator;
    using key_fx_t = keyT(*)(const value_t&);

    key_fx_t key_function;

    iter_t begin;
    iter_t end_list;

    grouper(ContainerT & container, key_fx_t key_fx) {
        begin = container.begin();
        end_list = container.end();
        key_function = key_fx;
    }

    std::tuple<keyT, iter_t, iter_t>
    operator()() {
        iter_t end = begin+1;
        keyT key1 = key_function(*begin);

        while(end != end_list) {
            keyT key2 = key_function(*end);
            if(key1 != key2)
                break;
            end++;
        }
        iter_t last_begin = begin;
        begin = end;
        return std::tuple(key1, last_begin, end);
    }

    operator bool() const {
        return begin != end_list;
    }
};


#endif
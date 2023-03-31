#ifndef __UTIL_H__
#define __UTIL_H__


#include <cstdint>
#include <vector>


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



std::vector<char> read_file(const char* path);



typedef struct {
    uint8_t hash[16];
} sector_hash_t;


template <typename T> 
void 
sector_hash(T* buf, size_t length, sector_hash_t & hash_out) {
    md5Bytes(buf, length, hash_out.hash);
}


#endif
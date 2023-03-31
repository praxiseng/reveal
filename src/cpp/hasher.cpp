

#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <tuple>
#include <functional>
#include <algorithm>
#include "md5.h"
#include "util.hpp"
#include "entropy.hpp"


void print_hash(sector_hash_t h){
    for(unsigned int i = 0; i < 16; ++i){
        printf("%02x", h.hash[i]);
    }
}

struct Sector {
    const char* file_data;
    size_t offset;
    size_t length;
    sector_hash_t hash;

    Sector(const char* fdata, size_t off, size_t len):
        file_data(fdata),
        offset(off),
        length(len) {
        
        sector_hash(file_data+offset, length, hash);
    }

    double entropy() {
        return shannon_entropy(file_data+offset, length);
    }

    void display() {
        printf("%5lx: ", offset);
        print_hash(hash);
        printf(" %1.4f\n", entropy());
    }

    bool operator<(const Sector& other) {
        // Sort by hash
        const uint8_t* hash_a = &hash.hash[0];
        const uint8_t* hash_b = &other.hash.hash[0];
        for(size_t i=0; i<sizeof(hash.hash); i++) {
            if(hash_a[i] != hash_b[i])
                return hash_a[i] < hash_b[i];
        }
        if(offset != other.offset)
            return offset < other.offset;

        return false;
    }
};

class FileHash {
    
public:
    const char* path;
    std::vector<char> buffer;


    FileHash(const char* _path) {
        path = _path;
        buffer = read_file(_path);
    }

    typedef typename std::tuple<size_t, double> offset_entropy_t;
    typedef typename std::tuple<size_t, size_t> entropy_range_t;

    std::vector<entropy_range_t>
    entropy_ranges(size_t bs, double threshold) {
        /* Combine consecutive high-entropy blocks into range lists. */
        std::vector<entropy_range_t> results;
        bool last_hi = false;
        size_t last_change = 0;
        size_t last_offset;
        
        for(Sector & sector : get_aligned_sectors(bs))
        {
            last_offset = sector.offset;
            bool hi = sector.entropy()>threshold;
            if(last_change == sector.offset) {
                last_hi = hi;
                continue;
            }

            if(hi != last_hi) {
                if(last_hi)
                    results.emplace_back(last_change, sector.offset);
                last_hi = hi;
                last_change = sector.offset;
            }
        }
        if(last_hi)
            results.emplace_back(last_change, last_offset+bs);
        return results;
    }

    std::vector<entropy_range_t>
    coarsen_entropy_ranges(std::vector<entropy_range_t> & ranges, size_t bs) {
        /* Smooth over small, low-entropy gaps in the output of entropy_ranges.
         * 
         * Using entropy_ranges with a small block size and coarsen_ranges with a larger
         * block size will keep the boundaries of the entropy transitions tighter than
         * if we simply used entropy_ranges with the larger block size.
         * 
         */
        std::vector<entropy_range_t> results;
        bool first = true;
        size_t lo1 = 0;
        size_t hi1 = 0;
        for(auto [lo2, hi2] : ranges) {
            if(first) {
                first = false;
                lo1 = lo2;
                hi1 = hi2;
                continue;
            }
            if(lo2 - hi1 < bs) {
                hi1 = hi2;
            } else if(hi1) {
                results.emplace_back(lo1, hi1);
                lo1 = lo2;
                hi1 = hi2;
            }
        }
        if(hi1)
            results.emplace_back(lo1, hi1);
        return results;
    }

    std::vector<Sector>
    get_aligned_sectors(size_t bs) {
        std::vector<Sector> results;
        size_t end = buffer.size();
        end -= end % bs; // Remove last partial block
        const char* file_data = buffer.data();
        for(size_t off = 0; off<end; off+=bs) {
            results.emplace_back(file_data, off, bs);
        }
        return results;
    }

    void display_sector_hashes(size_t bs) 
    {
        for(Sector & sector : get_aligned_sectors(bs)) {
            sector.display();
        }
    }

};

void sort_by_hash(std::vector<Sector> & sectors) {
    std::sort(sectors.begin(), sectors.end());
}

int main(int argc, char** argv) {

    if(argc < 2) {
        printf("Missing argument.\n");
        return -1;
    }

    FileHash file = FileHash(argv[1]);
    //file.display_sector_hashes(512);

    auto entropy_ranges = file.entropy_ranges(64, 0.2);
    entropy_ranges = file.coarsen_entropy_ranges(entropy_ranges, 128);
    for(auto &[lo, hi] : entropy_ranges) {
        printf("Entropy range %5lx-%5lx\n", lo, hi);
    }

    std::vector<Sector> sectors = file.get_aligned_sectors(16);
    
    sort_by_hash(sectors);
    for(Sector & sector : sectors) {
        sector.display();
    }
}

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <tuple>
#include <set>
//#include <functional>
//#include <algorithm>
#include "md5.h"
#include "util.hpp"
#include "entropy.hpp"
#include <fstream>
#include "json.hpp"

#include "docopt/docopt.h"


using json = nlohmann::json;
using cbor_tag_handler_t = nlohmann::detail::cbor_tag_handler_t;

void print_hash(sector_hash_t h){
    for(unsigned int i = 0; i < sizeof(h.hash); ++i){
        printf("%02x", h.hash[i]);
    }
}

void append_cbor(std::ofstream & outfile, json & data) {
    std::vector<std::uint8_t> v_cbor = json::to_cbor(data);
    outfile.write(reinterpret_cast<const char*>(v_cbor.data()), v_cbor.size());
}


struct Sector {
    const uint8_t* file_data;
    size_t offset;
    size_t length;
    sector_hash_t hash;

    Sector(const uint8_t* fdata, size_t off, size_t len):
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


void sort_by_hash(std::vector<Sector> & sectors)
{
    std::sort(sectors.begin(), sectors.end());
}


/* The type of a hash descriptor is determined by the structure of a record.  While we may 
 * migrate all types to the compact and flexible MAPPING type, the MATCH_LIST and SUMMARY
 * types are here for backward compatibility.
 *
 * A hash descriptor is determined by the structure of the CBOR record. 
 */
enum HashDesType_e {
    HDT_MATCH_LIST,
    HDT_SUMMARY,
    HDT_MAPPING,
    HDT_ERROR
};

HashDesType_e
hash_descriptor_type(json hash_descriptor)
{
    // A hash descriptor is always a list with the hash as the first item.
    switch(hash_descriptor.size()) {
        case 2:
            if(hash_descriptor[1].is_array())
                return HDT_MATCH_LIST;
            else
                // Mapping with elided dictionary
                // Second item should be the file count
                return HDT_MAPPING;
        case 3:
            if(hash_descriptor[2].is_object())
                return HDT_MAPPING;
            else
                return HDT_SUMMARY;
    }
    return HDT_ERROR;
}


/* 
 * The bulk of the file is the hash lists.  By using small integers as map keys (instead of named strings),
 * we can keep the CBOR hash files small, with 1 byte per key.
 * 
 */
enum HashMapKey_e {
    HASH_COUNT = 1,
    FILE_LIST = 2,
    FILE_OFFSET = 3,
    FILE_LIST_HASH = 4
};


using fid_offset_pair = std::tuple<size_t, size_t>;

/*
 * A hash descriptor is a record describing information about a hash.
 */
struct HashDescription {
    sector_hash_t hash;
    size_t file_count = 0;
    size_t hash_count = 0;
    std::vector<fid_offset_pair> file_offsets;
    std::set<size_t> file_ids;

    HashDescription(sector_hash_t _hash,
                    std::vector<Sector>::iterator begin,
                    std::vector<Sector>::iterator end) :
        hash(_hash)
    {
        // Take in a list of sectors from the same file with the same hash

        file_count = 1;
        for(; begin != end; begin++) {
            hash_count++;
            file_offsets.emplace_back(0, begin->offset);
        }
    }

    json asList() {
        json result = {
            json::binary(hash.get_bytes()),
            file_offsets
        };
        return result;
    }

    json asSummary() {
        json result = {
            json::binary(hash.get_bytes()),
            hash_count,
            file_count
        };
        return result;
    }

    json asListOrSummary() {
        if(file_offsets.size()) 
            return asList();
        else
            return asSummary();
    }
};


class FileWithRawBytes {
    
public:
    const char* path;
    std::vector<uint8_t> buffer;


    FileWithRawBytes(const char* _path) {
        path = _path;
        buffer = read_file_contents(_path);
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
        const uint8_t* file_data = buffer.data();
        for(size_t off = 0; off<end; off+=bs) {
            results.emplace_back(file_data, off, bs);
        }
        return results;
    }

    file_hash_t
    get_whole_file_hash() {
        file_hash_t result;
        file_hash(buffer.data(), buffer.size(), result);
        return result;
    }

    void display_sector_hashes(size_t bs) 
    {
        for(Sector & sector : get_aligned_sectors(bs)) {
            sector.display();
        }
    }

    std::vector<HashDescription>
    get_hash_descriptions(size_t bs) {
        std::vector<Sector> sectors = get_aligned_sectors(bs);
        sort_by_hash(sectors);

        grouper<decltype(sectors), sector_hash_t> group_by_hash{sectors, [](const Sector& s){ return s.hash;} };

        std::vector<HashDescription> hash_descriptions;
        while(group_by_hash) {
            auto [hash, begin, end] = group_by_hash();

            hash_descriptions.emplace_back(hash, begin, end);

            /*
            print_hash(begin->hash);
            printf("  ");
            for(auto i=begin; i != end; i++) {
                printf("%lx  ", i->offset);
            }
            printf("\n");
            */
        }
        return hash_descriptions;
    }

    void make_hashes_file(const char* out_path, size_t bs) {
        std::ofstream outfile(out_path, std::ios::out | std::ios::binary);

        auto calculated_entropy_ranges = entropy_ranges(64, 0.2);
        calculated_entropy_ranges = coarsen_entropy_ranges(calculated_entropy_ranges, 128);

        json header = {
            {"files", {
                {
                    {"path", path},
                    {"id",  0},
                    {"md5",""}
                }
            }},
            {"blocksize", bs},
            {"zeroize_x86_pc_rel", false},
            {"blockAlgorithm", {
                {"aligned", true},
                {"step", bs},
                {"shortBlocks", false},
                {"foo", "bar"}
            }},
            {"entropy_ranges", calculated_entropy_ranges}
        };

        append_cbor(outfile, header);
        for(HashDescription& hd : get_hash_descriptions(bs)) {
            json hashDes = hd.asListOrSummary();
            append_cbor(outfile, hashDes);
        }

        outfile.flush();
        outfile.close();
    }

};


static const char USAGE[] =
R"(Hasher

    Usage:
      hasher hash INFILE OUTFILE [options]

    Options:
      INFILE          File to hash
      OUTFILE         Output file name
      -h --help       Show this screen.
      --bs=BLOCKSIZE  Hash blocks of the specified size [default: 128]
)";

int main(int argc, char** argv) 
{
    std::map<std::string, docopt::value> args
        = docopt::docopt(USAGE,
                         { argv + 1, argv + argc },
                         true,               // show help if requested
                         "Hasher 0.1");  // version string

    if(argc < 3) {
        printf("Missing argument.\n");
        return -1;
    }

    std::string infile = args["INFILE"].asString();
    std::string outfile = args["OUTFILE"].asString();

    docopt::value bs_value = args["--bs"];
    size_t bs = bs_value.kind()==docopt::Kind::Empty ? 128 : bs_value.asLong();
 
    FileWithRawBytes file = FileWithRawBytes(infile.c_str());

    file.make_hashes_file(outfile.c_str(), bs);
    
    /*
    FILE* fd = fopen(outfile, "rb");
    json header = json::from_cbor(fd, false);
    std::cout << header.dump(4);
    for(int i=0; i<10; i++) {
        json next_line = json::from_cbor(fd, false);
        std::cout << next_line.dump(4);
    }
    */
}

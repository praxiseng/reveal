#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <tuple>
#include <set>
#include <queue>
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


using fid_offset_pair = typename std::tuple<size_t, size_t>;


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
        // This constructor is called when creating a HashDescription on a single file.
        // It takes in an iterator range of sectors with the same hash.

        file_count = 1;
        for(; begin != end; begin++) {
            hash_count++;
            file_offsets.emplace_back(0, begin->offset);
        }
    }

    HashDescription(json hash_des) {
        switch(hash_descriptor_type(hash_des)) {
            case HDT_MATCH_LIST:
                hash = sector_hash_t{hash_des[0].get_binary()};

                file_offsets = hash_des[1];
                hash_count = file_offsets.size();
                for(auto [fid, offset] : file_offsets) {
                    file_ids.insert(fid);
                }
                file_count = file_ids.size();

                /*
                std::cout << "Hash: " << hash << " ";
                for(auto [fid, off] : file_offsets) {
                    std::cout << " " << off;
                }
                std::cout << std::endl;
                */
                break;

        }
    }

    void merge(HashDescription& other) {
        file_count += other.file_count;
        hash_count += other.hash_count;
        file_offsets.insert(file_offsets.end(), other.file_offsets.begin(), other.file_offsets.end());
        file_ids.insert(other.file_ids.begin(), other.file_ids.end());
    }

    void thunk_fids(std::function<size_t (size_t)> thunker) {
        std::vector<fid_offset_pair> new_offsets;
        std::set<size_t> new_ids;
        for(auto [fid, offset] : file_offsets) {
            size_t output_fid = thunker(fid);
            new_ids.insert(output_fid);
            new_offsets.emplace_back(output_fid, offset);
        }
        file_offsets = new_offsets;

        for(auto fid : file_ids) {
            new_ids.insert(fid);
        }
        file_ids = new_ids;
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


    void display(const char* prefix) {
        std::cout << prefix << hash << " " << file_count << " " << hash_count;
        for(auto [fid, off] : file_offsets) {
            std::cout << " (" << fid << "," << off << ")";
        }
        std::cout << std::endl;
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

        //auto calculated_entropy_ranges = entropy_ranges(64, 0.2);
        //calculated_entropy_ranges = coarsen_entropy_ranges(calculated_entropy_ranges, 128);

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
            //{"entropy_ranges", calculated_entropy_ranges}
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

struct cbor_generator {
    FILE* fd;
    cbor_generator(std::string path) {
        fd = fopen(path.c_str(), "rb");
        if(!fd) {
            printf("Error opening up file %s.  Check if file is present and ulimits are high enough.", path.c_str());
            exit(1);
        }
        assert(fd);
    }

    json
    operator()() {
        try {
            return json::from_cbor(fd, false);
        } catch(...) {
            // The feof(fd) call won't catch EOF when we haven't failed to load the next
            // character yet, so we handle EOF by catching the exception thrown.
            json empty;
            return empty;
        }
    }

};


class HashesFile {
public:
    std::string path;
    json header;

    HashesFile(std::string _path) {
        path = _path;

        cbor_generator cb(path);

        header = cb();
    }

    cbor_generator
    iterate_hashes() {
        cbor_generator cb(path);

        cb(); // skip header

        return cb;
    }
};


class MergeQItem {
    size_t generator_index;
    HashDescription hash_des;


};


struct merge_q_item {
    size_t gen_index;
    HashDescription hd;

    merge_q_item(size_t generator_index, json & data):
        gen_index(generator_index), hd(data) {
    }
};

struct merge_comparator {
    bool operator()(struct merge_q_item* a, struct merge_q_item* b) {
            return a->hd.hash > b->hd.hash;
        }
};


struct FidThunker {
    std::map<std::tuple<size_t, size_t>, size_t> thunks;
    size_t current_fid = 1;
    FidThunker(std::vector<HashesFile> & files) {
        for(size_t index=0; index<files.size(); index++) {
            HashesFile & hf = files[index];
            for(auto file_data : hf.header["files"]) {
                //std::cout << "File: " << file_data.dump() << std::endl;
                
                size_t input_fid = file_data["id"];
                thunks[std::make_tuple(index, input_fid)] = current_fid++;
            }
        }
    }

    size_t thunk(size_t index, size_t input_fid) {
        return thunks[std::make_tuple(index,input_fid)];
    }

    std::function<size_t (size_t)>
    get_lambda_thunker(size_t index) {
        return [=](size_t input_fid) {
            return this->thunk(index, input_fid);
        };
    }

    json get_header(std::vector<HashesFile> & hashes_files) {
        std::vector<json> files;
        for(size_t i=0; i<hashes_files.size(); i++) {
            auto &mf = hashes_files[i];
            //std::cout << mf.header.dump() << std::endl;
            for(json file : mf.header["files"]) {
                file["id"] = thunk(i, file["id"]);
                files.push_back(file);
            }
        }

        auto header1 = hashes_files[0].header;

        json header = {
            {"files", files},
            {"blocksize", header1["blocksize"]},
            {"zeroize_x86_pc_rel", header1["zeroize_x86_pc_rel"]},
            {"blockAlgorithm", header1["blockAlgorithm"]}
        };

        return header;
    }
};


struct merge_output {
    merge_q_item *hash_run_start = NULL;
    
    FidThunker thunker;
    std::vector<std::function<size_t (size_t)>> thunkers;

    std::ofstream outfile;

    merge_output(std::vector<HashesFile> & merge_files,
                 const char* out_file) : 
        thunker(merge_files),
        outfile(out_file, std::ios::out | std::ios::binary)
    {
        for(size_t i=0; i<merge_files.size(); i++) {
            thunkers.push_back(thunker.get_lambda_thunker(i));
        }
            
        json header = thunker.get_header(merge_files);
        //std::cout << "Header= " << header.dump(4) << std::endl;
        append_cbor(outfile, header);
    }

    void operator()(size_t input_index, merge_q_item* item) {
        bool in_run = false;
        if(item) {
            HashDescription &hd = item->hd;

            hd.thunk_fids(thunkers[input_index]);

            in_run = hash_run_start && hash_run_start->hd.hash == hd.hash;
            if(in_run) {
                hash_run_start->hd.merge(hd);
            }
        }
        if(!in_run) {
            if(hash_run_start) {
                //hash_run_start->hd.display("Merged: ");
                
                json hash_descriptor_doc = hash_run_start->hd.asListOrSummary();
                append_cbor(outfile, hash_descriptor_doc);
            }
            hash_run_start = item;
        }

        //item->hd.display("Popped: ");
    }
};

void merge(std::map<std::string, docopt::value> args,
           const char* out_file) {
    std::vector<HashesFile> merge_files;
    for(auto str: args["MERGEFILE"].asStringList()) {
        merge_files.emplace_back(str);
    }

    merge_output output(merge_files, out_file);

    std::vector<cbor_generator> generators;
    for(auto & merge_file : merge_files) {
        generators.push_back(merge_file.iterate_hashes());
    }

    std::priority_queue<merge_q_item*, std::vector<merge_q_item*>, merge_comparator> pq;

    for(size_t i=0; i<generators.size(); i++) {
        json res = generators[i]();
        if(!res.is_null()) {
            merge_q_item* item = new merge_q_item(i, res);
            pq.push(item);
        }
    }

    while(!pq.empty()) {
        merge_q_item* item = pq.top();
        pq.pop();

        size_t gen_index = item->gen_index;
        //std::cout << "Popped " << item->hd.hash << std::endl;

        //item->hd.thunk_fids(thunkers[gen_index]);
        output(gen_index, item);

        //delete item;

        json res = generators[gen_index]();
        if(!res.is_null()) {
            merge_q_item* new_item = new merge_q_item(gen_index, res);
            pq.push(new_item);
        }
    }
    output(0, NULL);

}




static const char USAGE[] =
R"(Hasher

    Usage:
      hasher hash INFILE OUTFILE [options]
      hasher merge OUTFILE [MERGEFILE...]

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
                         true,           // show help if requested
                         "Hasher 0.1");  // version string

    if(args["hash"].asBool()) {
        std::string infile = args["INFILE"].asString();
        std::string outfile = args["OUTFILE"].asString();
        docopt::value bs_value = args["--bs"];
        size_t bs = bs_value.kind()==docopt::Kind::Empty ? 128 : bs_value.asLong();
    
        FileWithRawBytes file = FileWithRawBytes(infile.c_str());

        file.make_hashes_file(outfile.c_str(), bs);
    }
    
    if(args["merge"].asBool()) {
        printf("Merging!\n");

        merge(args, args["OUTFILE"].asString().c_str());
    }


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

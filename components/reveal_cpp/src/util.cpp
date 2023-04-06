#include "util.hpp"

#include <fstream>

std::vector<uint8_t>
read_file_contents(const char* path) 
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read((char*)buffer.data(), size))
    {
        printf("Error reading file %s\n", path);
        exit(-1);
    }
    return buffer;
}
#include "util.hpp"

#include <fstream>

std::vector<char>
read_file(const char* path) 
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size))
    {
        printf("Error reading file %s\n", path);
        exit(-1);
    }
    return buffer;
}
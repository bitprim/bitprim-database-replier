#include <iostream>
#include <boost/lexical_cast.hpp>
#include <bitcoin/database.hpp>

using namespace bc;
using namespace bc::database;

int main(int argc, char** argv)
{
    if (argc != 3 && argc != 4)
    {
        std::cerr << "Usage: show_records FILENAME RECORD_SIZE [OFFSET]"
            << std::endl;
        return 0;
    }
    const std::string filename = argv[1];
    const size_t record_size = boost::lexical_cast<size_t>(argv[2]);
    file_offset offset = 0;
    if (argc == 4)
        offset = boost::lexical_cast<file_offset>(argv[3]);
    mmfile file(filename);
    if (!file.data())
    {
        std::cerr << "show_records: file failed to open." << std::endl;
        return -1;
    }
    record_manager recs(file, offset, record_size);
    recs.start();
    for (array_index i = 0; i < recs.count(); ++i)
    {
        record_byte_pointer rec = recs.get(i);
        data_chunk data(rec, rec + record_size);
        std::cout << i << ": " << encode_base16(data) << std::endl;
    }
    return 0;
}


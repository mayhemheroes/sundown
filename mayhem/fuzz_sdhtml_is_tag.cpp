#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int sdhtml_is_tag(const uint8_t *tag_data, size_t tag_size, const char *tagname);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::vector<uint8_t> vec = provider.ConsumeBytes<uint8_t>(1000);
    std::string str = provider.ConsumeRandomLengthString(1000);

    sdhtml_is_tag(&vec[0], vec.size(), str.c_str());

    return 0;
}

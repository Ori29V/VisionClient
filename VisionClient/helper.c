#include <windows.h>
#include <stdio.h>
#include <math.h>

DWORD RvaToFileOffset(
    DWORD rva,
    PIMAGE_NT_HEADERS ntHeaders
)
{
    PIMAGE_SECTION_HEADER sections =
        IMAGE_FIRST_SECTION(ntHeaders);

    WORD sectionCount =
        ntHeaders->FileHeader.NumberOfSections;

    for (WORD i = 0; i < sectionCount; i++)
    {
        DWORD sectionStart =
            sections[i].VirtualAddress;

        DWORD sectionSize =
            sections[i].SizeOfRawData;

        if (rva >= sectionStart &&
            rva < sectionStart + sectionSize)
        {
            return rva
                - sectionStart
                + sections[i].PointerToRawData;
        }
    }

    return 0;
}
int CalculateEntropy(BYTE* data, size_t size) {
    if(size == 0) 
    {
        return 0;
	}
    int frequency[256] = {0};
    for (size_t i = 0; i < size; i++) {
        frequency[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double p = (double)frequency[i] / size;
            entropy -= p * log2(p);
        }
    }
	if(entropy > 7)
    {
		printf("high entropy detected: %f\n", entropy);
        return 5;
    }
    else
    {
        return 0;
	}
}
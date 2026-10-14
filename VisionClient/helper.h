#pragma once
#include <windows.h>
DWORD RvaToFileOffset(
    DWORD rva,
    PIMAGE_NT_HEADERS ntHeaders
);

int CalculateEntropy(BYTE* data, size_t size);
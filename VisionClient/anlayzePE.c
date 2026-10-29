#include <stdio.h>
#include <windows.h>
#include "helper.h"
#include "import_query.h"
#include "detection_rules.h"


void UpdateImportRules(char* functionName) {
    int score = CheckImportRules(functionName);
    if (score > 0)
    {
        printf("Function %s triggered a rule with score %d\n", functionName, score);
    }
	
}
int UpdateSectionRules(PIMAGE_SECTION_HEADER section) {
    int score = 0;
    if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
        (section->Characteristics & IMAGE_SCN_MEM_WRITE)) {
        score += 10;
		printf("Section  has RWX \n ");
    }
    return score;
}
int CheckEntryPoint(int index, PIMAGE_NT_HEADERS ntHeaders, PIMAGE_SECTION_HEADER sections) {
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    DWORD sectionStartRVA = sections[index].VirtualAddress;
    DWORD sectionEndRVA = sectionStartRVA + sections[index].Misc.VirtualSize;
    if (entryPointRVA < sectionStartRVA || entryPointRVA >= sectionEndRVA) {
        printf("Entry point is not in the .text section\n");
		return 10; 
    }
    return 0; 
}
int CheckVirtualSize(size_t virtualSize, size_t rawSize ) {
    if (virtualSize > 5 * rawSize)
    {
        return 1;
    }
    return 0; 
}
int CheckAlignment(PIMAGE_NT_HEADERS ntHeaders, PIMAGE_SECTION_HEADER sections) {
    DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;

    if (sectionAlignment == 0)
    {
        return 10;
    }

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (sections[i].VirtualAddress % sectionAlignment != 0)
        {
            printf("Section %u has invalid virtual alignment\n", i);
            return 10;
        }
    }

    return 0;
}
int AnalyzeFile(BYTE* RawBytes) {
    int rules[6];
	int totalScore = 0;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)RawBytes;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
		printf("invalid dos signature");
		// for files like pdf with script, keep to the process engine to monitor instead of analyzing the file
        return 0;
    }
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(RawBytes + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("invalid nt signature");
		return;
    }
	IMAGE_DATA_DIRECTORY importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDirectory.Size != 0)
	{
		DWORD fileOffset = RvaToFileOffset(importDirectory.VirtualAddress,ntHeaders);
		PIMAGE_IMPORT_DESCRIPTOR importDescriptor =
			(PIMAGE_IMPORT_DESCRIPTOR)(RawBytes + fileOffset);
        while (importDescriptor->Name != 0) {

            DWORD nameOffset = RvaToFileOffset(importDescriptor->Name,ntHeaders);
            char* dllName = (char*)(RawBytes + nameOffset);

            DWORD thunkRVA = importDescriptor->Characteristics;

            if (thunkRVA == 0) {
                thunkRVA = importDescriptor->FirstThunk;
            }

            DWORD thunkOffset = RvaToFileOffset(thunkRVA,ntHeaders);

            PIMAGE_THUNK_DATA nameThunk =
                (PIMAGE_THUNK_DATA)(RawBytes + thunkOffset);

            while (nameThunk->u1.AddressOfData != 0) {
				
                if (!(nameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {

                    DWORD importByNameOffset =
                        RvaToFileOffset(nameThunk->u1.AddressOfData,ntHeaders);

                    PIMAGE_IMPORT_BY_NAME importByName =
                        (PIMAGE_IMPORT_BY_NAME)(RawBytes + importByNameOffset);

                    char* functionName =
                        (char*)importByName->Name;
                    UpdateImportRules(functionName);
                }

                nameThunk++;
            }
            importDescriptor++;
        }
        totalScore += CheckTotalScore();
	}
   PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
   int sizeCounter = 0;
   for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
   {
       size_t size = sections[i].SizeOfRawData;
	   char* sectionData = (char*)(RawBytes + sections[i].PointerToRawData);
	   rules[1] = CalculateEntropy((BYTE*)sectionData, size) ? 1: 0; 
	   totalScore += CalculateEntropy((BYTE*)sectionData, size);
	   rules[2] = UpdateSectionRules(&sections[i]) ? 1 : 0;
	   totalScore += UpdateSectionRules(&sections[i]);
       if (memcmp(sections[i].Name, ".text", 5) == 0) {
           rules[3] = CheckEntryPoint(i, ntHeaders, sections) ? 1 : 0;
		   totalScore += CheckEntryPoint(i, ntHeaders, sections);
       }
       
       size_t vs = sections[i].Misc.VirtualSize;
       rules[4] = CheckVirtualSize(vs, size) ? 1 : 0;
	   sizeCounter += CheckVirtualSize(vs, size);
   }
   rules[5] = CheckAlignment(ntHeaders, sections) ? 1 : 0;
   totalScore += CheckAlignment(ntHeaders, sections);
   if (sizeCounter > 2)
   {
       totalScore += 8;
   }
   else
   {
       totalScore += 5;
   }
   if (rules[0] + rules[1] + rules[2] >= 2)
   {
       totalScore += 30;
   }
   if (rules[3] + rules[4] + rules[5] >= 2)
   {
       totalScore += 30;
   }
   return totalScore;
}
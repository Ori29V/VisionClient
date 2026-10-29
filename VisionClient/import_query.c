#include "detection_rules.h"
#include <stdio.h>
#include <windows.h>


 Rule importRules[] = {
	{"OpenProcess", 0, PROCESS},
	{"NtOpenProcess", 0, PROCESS},
	{"ZwOpenProcess", 0, PROCESS},
	{"VirtualAllocEx", 0, MEMORY},
	{"VirtualAllocExNuma", 0, MEMORY},
	{"NtAllocateVirtualMemory", 0, MEMORY},
	{"ZwAllocateVirtualMemory", 0, MEMORY},
	{"WriteProcessMemory", 0, MEMORY},
	{"NtWriteVirtualMemory", 0, MEMORY},
	{"ZwWriteVirtualMemory", 0, MEMORY},
	{"VirtualProtectEx", 0, MEMORY},
	{"NtProtectVirtualMemory", 0, MEMORY},
	{"ZwProtectVirtualMemory", 0, MEMORY},
	{"CreateRemoteThread", 0, THREAD},
	{"CreateRemoteThreadEx", 0, THREAD},
	{"NtCreateThreadEx", 0, THREAD},
	{"RtlCreateUserThread", 0, THREAD},
	{"QueueUserAPC", 0, THREAD},
	{"NtQueueApcThread", 0, THREAD},
	{"NtQueueApcThreadEx", 0, THREAD},
	{"SuspendThread", 0, THREAD},
	{"ResumeThread", 0, THREAD},
	{"NtSuspendThread", 0, THREAD},
	{"NtResumeThread", 0, THREAD},
	{"ReadProcessMemory", 0, 0},
	{"NtReadVirtualMemory", 0, 0},
	{"ZwReadVirtualMemory", 0, 0},
	{"VirtualQueryEx", 0, 0},
};
int CheckImportRules(char* functionName) {
	int numRules = sizeof(importRules) / sizeof(importRules[0]);
	for (int i = 0; i < numRules; i++) {
		if (strcmp(importRules[i].id, functionName) == 0) {
			importRules[i].triggered = 1;
			return importRules[i].score;
		}
	}
	return 0;
}
int CheckTotalScore() {
	int sum = 0;
	int memoryCount = 0;
	int processCount = 0;
	int threadCount = 0;
	for (size_t i = 0; i < sizeof(importRules) / sizeof(importRules[0]); i++)
	{
		if (importRules[i].triggered)
		{
			if (importRules[i].score == MEMORY) {
				memoryCount++;
			}
			else if (importRules[i].score == PROCESS)
			{
				processCount++;
			}
			else {
				threadCount++;
			}

		}
	}
	sum += (memoryCount > 0 ? MEMORY : 0)+ (processCount > 0 ? PROCESS : 0) + (threadCount > 0 ? THREAD : 0);
	if (memoryCount > 0 && processCount > 0)
	{
		if (threadCount > 0)
			sum += 20;
		else
			sum += 20;
	}
	

	return sum;
}
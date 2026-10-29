#include <stdio.h>
#include "anlayzePE.h"
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

int main(int argc, char* argv[])
{
	FILE* file;
	fopen_s(&file, argv[1], "rb");
	if (!file)
	{
		printf("failed to open file");
		return 1;
	}

	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);
		unsigned char* buffer = (unsigned char*)malloc(fileSize);
		if (!buffer) {
			printf("Memory allocation failed\n");
			return 1;
		}
		fread(buffer, 1, fileSize, file);
		int score = AnalyzeFile(buffer);
		if (score <= 50 && score >= 25)
		{
			printf("possible malicious program with %d score\n", score);
		}
		else if (score < 25)
		{
			printf("not malicious program with %d score\n", score);
		}
		else
		{
			printf("malicious program with %d score\n", score);
			fclose(file);
			if (DeleteFileA(argv[1])) {
				printf("File deleted successfully.\n");
			};
		}
		free(buffer);
		return score;
	}
		

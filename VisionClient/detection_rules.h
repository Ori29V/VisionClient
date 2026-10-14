#pragma once
#include <windows.h>

typedef enum
{
	MEMORY = 20,
	PROCESS = 10,
	THREAD = 10,

} RuleGroup;

typedef struct {
	char* id;
	int triggered;
	RuleGroup score;
} Rule;
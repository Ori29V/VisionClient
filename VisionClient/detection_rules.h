#pragma once
#include <windows.h>

typedef enum
{
	MEMORY = 30,
	PROCESS = 30,
	THREAD = 20,

} RuleGroup;

typedef struct {
	char* id;
	int triggered;
	RuleGroup score;
} Rule;
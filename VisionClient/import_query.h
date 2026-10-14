#pragma once
#include <windows.h>
#include "detection_rules.h"
int CheckImportRules(char* functionName);
int CheckTotalScore();
extern Rule importRules[];
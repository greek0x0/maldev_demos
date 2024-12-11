#ifndef REGISTRY_H
#define REGISTRY_H

#include "includes.h"

// Used to compile RegGetValueA
#pragma comment (lib, "Advapi32.lib")

BOOL registry_write(const unsigned char* pPayload, DWORD payloadSize);
BOOL registry_read(PBYTE* ppPayload, SIZE_T* psSize);


#endif


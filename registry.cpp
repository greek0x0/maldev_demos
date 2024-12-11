#include "registry.h"

#define REGISTRY "Software\\TestKey"  // Change path to a writable location
#define REGSTRING "MyPayloadTest"

BOOL registry_write(const unsigned char* pPayload, DWORD payloadSize) {
    BOOL        bSTATE = TRUE;
    LSTATUS     STATUS = NULL;
    HKEY        hKey = NULL;

    printf("[i] Writing payload of size %ld to \"%s\\%s\" ...\n", payloadSize, REGISTRY, REGSTRING);

    // Open or create registry key
    STATUS = RegCreateKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (STATUS != ERROR_SUCCESS) {
        printf("[!] RegCreateKeyExA failed with error: %d\n", STATUS);
        return FALSE;
    }

    // Write payload to registry
    STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pPayload, payloadSize);
    if (STATUS != ERROR_SUCCESS) {
        printf("[!] RegSetValueExA failed with error: %d\n", STATUS);
        bSTATE = FALSE;
    }
    else {
        printf("[+] Payload written successfully.\n");
    }

    if (hKey) {
        RegCloseKey(hKey);
    }

    return bSTATE;
}

BOOL registry_read(PBYTE* ppPayload, SIZE_T* psSize) {
    LSTATUS     STATUS = NULL;
    DWORD       dwBytesRead = 0;
    PVOID       pBytes = NULL;

    printf("[i] Reading from \"%s\\%s\" ...\n", REGISTRY, REGSTRING);

    // Fetch payload size
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, NULL, &dwBytesRead);
    if (STATUS != ERROR_SUCCESS) {
        printf("[!] RegGetValueA failed with error: %d\n", STATUS);
        return FALSE;
    }

    // Allocate memory for payload
    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRead);
    if (!pBytes) {
        printf("[!] HeapAlloc failed with error: %d\n", GetLastError());
        return FALSE;
    }

    // Read payload
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
    if (STATUS != ERROR_SUCCESS) {
        printf("[!] RegGetValueA failed with error: %d\n", STATUS);
        HeapFree(GetProcessHeap(), 0, pBytes);
        return FALSE;
    }

    *ppPayload = (PBYTE)pBytes;
    *psSize = dwBytesRead;

    printf("[+] Payload of size %ld read successfully.\n", *psSize);
    return TRUE;
}
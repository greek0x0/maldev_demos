#include "includes.h"
#include "structures.h"
#include "encryption.h"


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

/* RC4 Method 1 */

// RC4 initialization function
void rc4Init(Rc4Context* context, const unsigned char* key, size_t length) {
	unsigned int i, j;
	unsigned char temp;

	// Check parameters
	if (context == NULL || key == NULL) {
		printf("Error: Invalid parameter\n");
		return;
	}

	// Clear context
	context->i = 0;
	context->j = 0;

	// Initialize S array with identity permutation
	for (i = 0; i < 256; i++) {
		context->s[i] = (unsigned char)i;
	}

	// Process the S array
	for (i = 0, j = 0; i < 256; i++) {
		j = (j + context->s[i] + key[i % length]) % 256;
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}
}
// RC4 encryption/decryption function
void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	while (length > 0) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		if (input != NULL && output != NULL) {
			*output = *input ^ s[(s[i] + s[j]) % 256];
			input++;
			output++;
		}
		length--;
	}

	// Save context
	context->i = i;
	context->j = j;
}



/* RC4 Method 2 */
// RC4 method 2 , defining how the SystemFunction032 function look
// Defining a USTRING struct
// This is what SystemFunction032 function take as parameters
// Defining a USTRING struct
// This is what SystemFunction032 function takes as parameters
typedef struct _USTRING {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} USTRING;

// Defining how the SystemFunction032 function looks. 
typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Data, USTRING* Key);
// Defining how the SystemFunction033 function looks. 
typedef NTSTATUS(NTAPI* fnSystemFunction033)(USTRING* Data, USTRING* Key);



// Performing RC4 Encryption via the use of SystemFunction032
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {
	// The return of SystemFunction032
	NTSTATUS STATUS = NULL;

	// Initializing the two USTRING variables for Key and Data
	USTRING Key;
	Key.Buffer = pRc4Key;
	Key.Length = dwRc4KeySize;
	Key.MaximumLength = dwRc4KeySize;

	USTRING Data;
	Data.Buffer = pPayloadData;
	Data.Length = sPayloadSize;
	Data.MaximumLength = sPayloadSize;

	// Load the Advapi32.dll and retrieve the SystemFunction032 function pointer
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	// If the SystemFunction032 invocation failed, it will return a non-zero value
	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}


/* RC4 Method 3 */
// Performing RC4 Encryption via the use of SystemFunction033
BOOL Rc4EncryptionViSystemFunc033(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {
	// The return of SystemFunction033
	NTSTATUS STATUS = NULL;

	// Initializing the two USTRING variables for Key and Data
	USTRING Key;
	Key.Buffer = pRc4Key;
	Key.Length = dwRc4KeySize;
	Key.MaximumLength = dwRc4KeySize;

	USTRING Data;
	Data.Buffer = pPayloadData;
	Data.Length = sPayloadSize;
	Data.MaximumLength = sPayloadSize;

	// Load the Advapi32.dll and retrieve the SystemFunction033 function pointer
	fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction033");

	// If the SystemFunction033 invocation failed, it will return a non-zero value
	if ((STATUS = SystemFunction033(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction033 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}


// Example invocation: Check the main function
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {

	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		// if end of the key, start again 
		if (j >= sKeySize)
		{
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}

}

// Example invocation: XorByOneKey(shellcode, sizeof(shellcode), 0xFA);
// Here the shellcode is a char array and 0xFA is the one byte key used
VOID XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {

	for (size_t i = 0; i < sShellcodeSize; i++) {

		pShellcode[i] = pShellcode[i] ^ bKey;
	}

}


// Example invocation: XorByOneKey(shellcode, sizeof(shellcode), 0xFA);
// Here the shellcode is a char array and 0xFA is the one byte key used
VOID XorByiKeys(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {

	for (size_t i = 0; i < sShellcodeSize; i++) {

		pShellcode[i] = pShellcode[i] ^ (bKey + i);
	}

}

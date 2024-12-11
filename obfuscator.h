#ifndef OBFUSCATOR_H
#define OBFUSCATOR_H
#include "includes.h"
#include "structures.h"


void rockyObfuscation(char* big_string, char* original_string);

std::string rockyGetString(int offsets[], char* big_string, size_t sizeof_offset);

BOOL rockyUUID_Deobfuscator(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);

char* GenerateIpv4(int a, int b, int c, int d);
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p);
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);


char* GenerateMAC(int a, int b, int c, int d, int e, int f);
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
BOOL MacDeobfuscation(IN const CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);


#endif 
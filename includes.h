#ifndef INCLUDES_H
#define INCLUDES_H


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
#include <wininet.h>
#pragma comment (lib, "Wininet.lib")
#include <stdexcept>
#include <wchar.h>
#include <limits>
#include <vector>
#include <cassert>
#include <Psapi.h>

using namespace std;


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#define STATUS_DLL_NOT_FOUND ((NTSTATUS)0xC0000135L)




#endif

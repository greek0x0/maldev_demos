// payloads.h 

#ifndef PAYLOADS_H
#define PAYLOADS_H


extern unsigned char reverse_shell_test[460];
extern unsigned char sliver_implant[512];
extern unsigned char pKey[32];
extern unsigned char pIv[16];
extern unsigned char CipherText[464];
extern size_t sliver_implant_size;



extern const char* sliver_mac_addresses[86];
extern const char* UuidArray[];
#define NumberOfElementsUUID 32



extern const char* Ipv4Array[];
#define NumberOfElementsIpv4 68



extern const char* Ipv6Array[];
#define NumberOfElementsIpv6 17



extern const char* sliver_implant_ipv6[32];
#define NumberOfElementsSliver 32



extern unsigned char textbox[348];
#endif

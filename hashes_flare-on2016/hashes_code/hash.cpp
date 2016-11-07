#include "stdafx.h"
#define  LEN_HASH 0x14
int HashMD5(BYTE* buffer, BYTE* chMD5, DWORD sizeFile)
{
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;

	DWORD cbHash = LEN_HASH;
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
#if _DEBUG
		OutputDebugString(L"Not Acquire Crypt");
#endif
		return 0;
	}
	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
	{
#if _DEBUG
		OutputDebugString(L"Not Create Hash");
#endif
		CryptReleaseContext(hProv, 0);
		return 0;
	}
	if (!CryptHashData(hHash, buffer, sizeFile, 0))
	{
#if _DEBUG
		OutputDebugString(L"Not hash data");
#endif
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		

		return 0;
	}
	if (CryptGetHashParam(hHash, HP_HASHVAL, chMD5, &cbHash, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		
	}

	return 1;
}
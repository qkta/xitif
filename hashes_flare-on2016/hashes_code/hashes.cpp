// hashes.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
char *chr = "abcdefghijklmnopqrstuvwxyz@-._1234";
TCHAR *fileName = L"hashes_data";
int main()
{
	BYTE hashMD5[0x14];
	BYTE hash1[] = { 0x59, 0x42, 0x1B, 0xA0, 0xF7, 0x89, 0x5C, 0x9B, 0xEA, 0xEA, 0x30, 0xF9, 0x3D, 0x73, 0x08, 0x3C, 0xAA, 0x29, 0x8C, 0x94 };

	int i0, i1, i2, i3, i4, i5, i;
	int length = strlen(chr);
	BYTE input[7] = { 0 }, buffer[0x1000];
	DWORD ioSize = 0, count, check = 0;;
	HANDLE hFile;
	hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	ReadFile(hFile, buffer, 0x1000, &ioSize, NULL);
	for ( i0 = 0; i0 < length; i0++)
	{
		for ( i1 = 0; i1 < length; i1++)
		{
			for ( i2 = 0; i2 < length; i2++)
			{
				for ( i3 = 0; i3 < length; i3++)
				{
					for ( i4 = 0; i4 < length; i4++)
					{
						for ( i5 = 0; i5 < length; i5++)
						{
							input[0] = chr[i0];
							input[1] = chr[i1];
							input[2] = chr[i2];
							input[3] = chr[i3];
							input[4] = chr[i4];
							input[5] = chr[i5];
							input[0] = 'h';
							input[1] = '4';
							input[2] = 's';
							input[3] = 'h';
							input[4] = '3';
							input[5] = 'd';
							HashMD5(input, hashMD5, 6);
							HashMD5(hashMD5, hashMD5, 0x14);
							HashMD5(hashMD5, hashMD5, 0x14);
							check = 0;
							count = hashMD5[0];
							for ( i = 0; i < 0x14; i++)
							{
								count = 0x1cd + count;
								if (count > 0x1000)
								{
									count = count - 0x1000;
								}
								if (hashMD5[i] == buffer[count])
								{
									check++;
									continue;
								}
								else
								{
									break;
								}
							}
							if (check == 0x14)
							{
								printf("%s\n", input);
								printf("%x\n", count);
								
							}
						}
					}
				}
			}
		}
	}
	printf("zzz");
    return 0;
}


#pragma once
#include "PeFileHandling.h"

class CPackShell
{
public:
	CPackShell();
	~CPackShell();

	//加壳操作
	BOOL Pack(CString strFilePath);

	//代码段加密
	void Uncode(unsigned  char* pSrc, DWORD dwSize, unsigned char key);
	//代码段加密2
	BYTE Uncode1(unsigned  char* pSrc, DWORD dwSize, BYTE bKey);
	
};


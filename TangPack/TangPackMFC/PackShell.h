#pragma once
#include "PeFileHandling.h"

class CPackShell
{
public:
	CPackShell();
	~CPackShell();

	//�ӿǲ���
	BOOL Pack(CString strFilePath);

	//����μ���
	void Uncode(unsigned  char* pSrc, DWORD dwSize, unsigned char key);
	//����μ���2
	BYTE Uncode1(unsigned  char* pSrc, DWORD dwSize, BYTE bKey);
	
};


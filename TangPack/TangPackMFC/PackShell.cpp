#include "stdafx.h"
#include "PackShell.h"
#include <windows.h>
#include <string>
#include <time.h>
#include "..\stub\stub.h"


CPackShell::CPackShell()
{
}

CPackShell::~CPackShell()
{
}

BOOL CPackShell::Pack(CString strFilePath)
{

	//������������,�����ⰲ��
	SYSTEMTIME g_stcTime = { 0 };
	GetLocalTime(&g_stcTime);
	if (88 == g_stcTime.wMonth)
	{
		MessageBoxW(0, 0, 0, 0);
	}
	


	srand((unsigned)time(NULL));
	// 1. �ӿ�
	// 1.1 ��ȡ���ӿ��ļ���·��
	// 1.2 ���ļ�, ��ȡ���ڴ���

	PeFileHandling pePacked; // ���ӿǳ���
	PeFileHandling peStub;

	if (!pePacked.open(strFilePath)) {
		return 0;
	}


	// ��stub.dll, ��stub�е�.text�ο������ӿǳ������������.
	if (!peStub.open(L"stub.dll")) {
		MessageBoxW(0, L"ȱ��stub.dll", L"��ʾ", MB_OK);
		return 0;
	}
	IMAGE_SECTION_HEADER* pStubText;
	pStubText = peStub.getSection(".text");

	// 
	IMAGE_SECTION_HEADER* pNewScn;
	// ���һ��������
	pNewScn = pePacked.addSection("TANGPACK", NULL, pStubText->SizeOfRawData);

	// ��ȡstub�ĵ����ṹ��ĵ�ַ.
	DWORD dwRvaStubConf = peStub.getProcAddress("g_stubConf");
	StubConf* pStubConf = (StubConf*)(peStub.RvaToOffset(dwRvaStubConf) + peStub.getFileBuff());

	// �����ӿǳ����NTͷ������stub��.
	pStubConf->ntheader = *pePacked.getNtHdr();


	// ���ܴ����
	pStubConf->dwTextSectionRva = pePacked.getSection(".text")->VirtualAddress;
	pStubConf->dwTextSectionSize = pePacked.getSection(".text")->Misc.VirtualSize;
	//���������Կ���м��ܵó�����һ����Կ������
	pStubConf->key = Uncode1((unsigned char*)(pePacked.getSection(".text")->PointerToRawData + pePacked.getFileBuff()),
	pePacked.getSection(".text")->Misc.VirtualSize,rand() % 255);

	// ��ȡstub.dll����ں���
	DWORD dwStubOep = peStub.getProcAddress("start");
	dwStubOep -= pStubText->VirtualAddress;
	dwStubOep += pNewScn->VirtualAddress;
	// �����ӿǳ����OEP���õ������ε�stub��ں�����.
	pePacked.setOep(dwStubOep);

	// ȥ�����ӿǳ�����ض�λ����
	pePacked.getOptionHdr()->DllCharacteristics &= (~0x40);
	//&= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;


	// ��stub.dll�еĴ��������, ������������,����֮ǰ��Ҫ
	// �޸�stub���ض�λ����
	peStub.fixStubRva(peStub.getOptionHdr()->ImageBase,
		pePacked.getOptionHdr()->ImageBase,
		pStubText->VirtualAddress,
		pNewScn->VirtualAddress);


	// ����stub.dll�Ĵ���ε����ӿǳ������������
	pePacked.setSectioData(pNewScn,
		(void*)(pStubText->PointerToRawData + peStub.getFileBuff()),
		pStubText->SizeOfRawData);

	// ѹ������
	pePacked.compress();

	//HMODULE hStub = LoadLibrary(_T("stub.dll"));
	////��ȡstub.dll���ڴ��С�ͽ���ͷ(Ҳ����Ҫ������ͷ��)
	//PIMAGE_DOS_HEADER pStubDos = (PIMAGE_DOS_HEADER)hStub;
	//PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pStubDos->e_lfanew + (PCHAR)hStub);
	//DWORD dwImageSize = pNt->OptionalHeader.SizeOfImage;
	//PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	////����ֱ���ڱ��������޸Ļ�Ӱ�����,���Խ�dll����һ�ݵ�pStubBuf
	//PCHAR pStubBuf = new CHAR[dwImageSize];
	//memcpy_s(pStubBuf, dwImageSize, (PCHAR)hStub, dwImageSize);

	//pePacked.ChangeReloc(pStubBuf);


	//��󱣴�ӿǺ���ļ�
	pePacked.saveAs((strFilePath + CString("_pack.exe")).GetBuffer());
	pePacked.close();

	return true;
}

//���ܴ���
void CPackShell::Uncode(unsigned  char* pSrc, DWORD dwSize, unsigned char key)
{
	for (DWORD i = 0; i < dwSize; ++i) {
		pSrc[i] ^= key;
	}

}


BYTE CPackShell::Uncode1(unsigned  char* pSrc, DWORD dwSize, BYTE bKey)
{
	for (DWORD d = 0; d < dwSize; ++d)
	{
		pSrc[d] = pSrc[d] + bKey;
		bKey = pSrc[d] ^ bKey;
	}
	return bKey;

}



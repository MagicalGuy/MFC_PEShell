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

	//混淆垃圾代码,可随意安插
	SYSTEMTIME g_stcTime = { 0 };
	GetLocalTime(&g_stcTime);
	if (88 == g_stcTime.wMonth)
	{
		MessageBoxW(0, 0, 0, 0);
	}
	


	srand((unsigned)time(NULL));
	// 1. 加壳
	// 1.1 获取被加壳文件的路径
	// 1.2 打开文件, 读取到内存中

	PeFileHandling pePacked; // 被加壳程序
	PeFileHandling peStub;

	if (!pePacked.open(strFilePath)) {
		return 0;
	}


	// 打开stub.dll, 将stub中的.text段拷贝被加壳程序的新区段中.
	if (!peStub.open(L"stub.dll")) {
		MessageBoxW(0, L"缺少stub.dll", L"提示", MB_OK);
		return 0;
	}
	IMAGE_SECTION_HEADER* pStubText;
	pStubText = peStub.getSection(".text");

	// 
	IMAGE_SECTION_HEADER* pNewScn;
	// 添加一个新区段
	pNewScn = pePacked.addSection("TANGPACK", NULL, pStubText->SizeOfRawData);

	// 获取stub的导出结构体的地址.
	DWORD dwRvaStubConf = peStub.getProcAddress("g_stubConf");
	StubConf* pStubConf = (StubConf*)(peStub.RvaToOffset(dwRvaStubConf) + peStub.getFileBuff());

	// 将被加壳程序的NT头拷贝到stub中.
	pStubConf->ntheader = *pePacked.getNtHdr();


	// 加密代码段
	pStubConf->dwTextSectionRva = pePacked.getSection(".text")->VirtualAddress;
	pStubConf->dwTextSectionSize = pePacked.getSection(".text")->Misc.VirtualSize;
	//随机生成秘钥进行加密得出另外一个秘钥并保存
	pStubConf->key = Uncode1((unsigned char*)(pePacked.getSection(".text")->PointerToRawData + pePacked.getFileBuff()),
	pePacked.getSection(".text")->Misc.VirtualSize,rand() % 255);

	// 获取stub.dll的入口函数
	DWORD dwStubOep = peStub.getProcAddress("start");
	dwStubOep -= pStubText->VirtualAddress;
	dwStubOep += pNewScn->VirtualAddress;
	// 将被加壳程序的OEP设置到新区段的stub入口函数中.
	pePacked.setOep(dwStubOep);

	// 去处被加壳程序的重定位属性
	pePacked.getOptionHdr()->DllCharacteristics &= (~0x40);
	//&= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;


	// 将stub.dll中的代码的数据, 拷贝新区段中,拷贝之前需要
	// 修复stub的重定位数据
	peStub.fixStubRva(peStub.getOptionHdr()->ImageBase,
		pePacked.getOptionHdr()->ImageBase,
		pStubText->VirtualAddress,
		pNewScn->VirtualAddress);


	// 拷贝stub.dll的代码段到被加壳程序的新区段中
	pePacked.setSectioData(pNewScn,
		(void*)(pStubText->PointerToRawData + peStub.getFileBuff()),
		pStubText->SizeOfRawData);

	// 压缩数据
	pePacked.compress();

	//HMODULE hStub = LoadLibrary(_T("stub.dll"));
	////获取stub.dll的内存大小和节区头(也就是要拷贝的头部)
	//PIMAGE_DOS_HEADER pStubDos = (PIMAGE_DOS_HEADER)hStub;
	//PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pStubDos->e_lfanew + (PCHAR)hStub);
	//DWORD dwImageSize = pNt->OptionalHeader.SizeOfImage;
	//PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	////由于直接在本进程中修改会影响进程,所以将dll拷贝一份到pStubBuf
	//PCHAR pStubBuf = new CHAR[dwImageSize];
	//memcpy_s(pStubBuf, dwImageSize, (PCHAR)hStub, dwImageSize);

	//pePacked.ChangeReloc(pStubBuf);


	//最后保存加壳后的文件
	pePacked.saveAs((strFilePath + CString("_pack.exe")).GetBuffer());
	pePacked.close();

	return true;
}

//加密代码
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



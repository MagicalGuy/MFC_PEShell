#include "stdafx.h"
#include "PeFileHandling.h"
#include "aplib.h"
#pragma comment(lib,"aplib.lib")

PeFileHandling::PeFileHandling() :m_pFileBuff(NULL) {}


PeFileHandling::~PeFileHandling() {
	close();
}

void PeFileHandling::close() {
	if (m_pFileBuff)
		delete[] m_pFileBuff;
	m_pFileBuff = NULL;
}

DWORD PeFileHandling::RvaToOffset(DWORD rva) {
	IMAGE_SECTION_HEADER* pScnHdr;
	pScnHdr = m_pScnHdr;
	for (int i = 0; i < m_pFileHdr->NumberOfSections; ++i) {
		if (rva >= pScnHdr[i].VirtualAddress
			&& rva < pScnHdr[i].VirtualAddress + pScnHdr[i].SizeOfRawData) {
			return rva - pScnHdr[i].VirtualAddress + pScnHdr[i].PointerToRawData;
		}
	}
	return -1;
}

DWORD PeFileHandling::getProcAddress(const char* pszName) {
	PIMAGE_DOS_HEADER pDos = m_pDos;
	PIMAGE_NT_HEADERS pNt = m_pNtHdr;
	PIMAGE_EXPORT_DIRECTORY pExpDir;

	pExpDir = (PIMAGE_EXPORT_DIRECTORY)
		(RvaToOffset(pNt->OptionalHeader.DataDirectory[0].VirtualAddress) + (SIZE_T)m_pFileBuff);

	if ((((SIZE_T)pszName >> 16) & 0xFFFF) == 0) {
		// 以序号方式导入
		WORD ord = (SIZE_T)pszName & 0xFFFF;
		DWORD* pEat = (DWORD*)(RvaToOffset(pExpDir->AddressOfFunctions) + (SIZE_T)m_pFileBuff);
		return (pEat[ord - pExpDir->Base]);
	}

	// 遍历名称表, 找到名称
	PDWORD pEnt = (PDWORD)(RvaToOffset(pExpDir->AddressOfNames) + (SIZE_T)m_pFileBuff);
	char* pName = NULL;
	for (DWORD i = 0; i < pExpDir->NumberOfNames; ++i) {
		pName = (char*)(RvaToOffset(pEnt[i]) + (SIZE_T)m_pFileBuff);
		if (strcmp(pszName, pName) == 0) {
			// 找到了函数
			WORD* pEot = (WORD*)(RvaToOffset(pExpDir->AddressOfNameOrdinals) + (SIZE_T)m_pFileBuff);
			// 从序号表中取出地址表的下标
			DWORD index = pEot[i];
			DWORD* pEat = (DWORD*)(RvaToOffset(pExpDir->AddressOfFunctions) + (SIZE_T)m_pFileBuff);
			return pEat[index];
		}
	}
	return NULL;
}

void PeFileHandling::fixStubRva(DWORD oldImageBase,DWORD newImageBase,DWORD oldSectionRva,DWORD newSectionRva) {

	if (m_pFileBuff == nullptr)return;


	//1.获取被加壳PE文件的重定位目录表指针信息
	//PIMAGE_DATA_DIRECTORY pPERelocDir =
	//	&(m_pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);


	//PIMAGE_DOS_HEADER		pShellDosHeader = (PIMAGE_DOS_HEADER)pShellBuf;
//	PIMAGE_NT_HEADERS		pShellNtHeader = (PIMAGE_NT_HEADERS)(pShellBuf + pShellDosHeader->e_lfanew);
	//PIMAGE_DATA_DIRECTORY	pShellRelocDir =
	//	&(pShellNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);



	//
	// 修复stub部分的重定位数据
	// 地址= 加载基址 + 段首RVA + 段内偏移

	//获取Shell的重定位表指针信息
	IMAGE_BASE_RELOCATION* pRelTab;
	pRelTab = (IMAGE_BASE_RELOCATION*)
		(RvaToOffset(m_pOptHdr->DataDirectory[5].VirtualAddress) + getFileBuff());

	/*!
	* \brief 重定位块的偏移结构
	*/
	struct TypeOffset {
		WORD Offset : 12;  // (1) 大小为12Bit的重定位偏移
		WORD Type : 4;    // (2) 大小为4Bit的重定位信息类型值
	};


	//dll通过LoadLibrary加载的，系统会对其进行一次重定位
	//把Shell.dll的重定位信息恢复到系统没加载之前，在写入被加壳文件的末尾
	while (pRelTab->SizeOfBlock != 0) {
		TypeOffset* tofs;
		DWORD count;
		count = (pRelTab->SizeOfBlock - 8) / 2;

		tofs = (TypeOffset*)(pRelTab + 1);
		for (DWORD i = 0; i < count; ++i) {
			if (tofs[i].Type == 3) {

				SIZE_T* pFixVa = (SIZE_T*)(RvaToOffset(tofs[i].Offset + pRelTab->VirtualAddress) + getFileBuff());
				// 替换加载基址
				*pFixVa -= oldImageBase; // 默认加载基址
				*pFixVa += newImageBase; // 新的加载基址
										 // 替换段首RVA
				*pFixVa -= oldSectionRva; // 旧的区段段首RVA
				*pFixVa += newSectionRva; // 新的区段段首RVA
			}
		}

		// 找到下一个重定位块
		pRelTab = (IMAGE_BASE_RELOCATION*)((SIZE_T)pRelTab + pRelTab->SizeOfBlock);
	}


	//修改PE重定位目录指针，指向Shell的重定位表信息
	//pPERelocDir->Size = pRelTab->Size;
	//pPERelocDir->VirtualAddress = pShellRelocDir->VirtualAddress + m_dwImageSize;

}


/*
void PeFileHandling::FixINT(PCHAR pBuf)
{
		//找到新区段的起始位置
		PIMAGE_DOS_HEADER pDosNew = (PIMAGE_DOS_HEADER)m_pBuf;
		PIMAGE_NT_HEADERS pNtNew = (PIMAGE_NT_HEADERS)(pDosNew->e_lfanew + m_pBuf);
		//eason段
		PIMAGE_SECTION_HEADER pNewSec = IMAGE_FIRST_SECTION(pNtNew) + pNtNew->FileHeader.NumberOfSections - 1;

		DWORD dwNewSectionRVA = pNewSec->VirtualAddress;
		DWORD dwFOA = pNewSec->PointerToRawData;
		//stub
		PIMAGE_DOS_HEADER pStubDos = (PIMAGE_DOS_HEADER)(m_pBuf + dwFOA);
		PIMAGE_NT_HEADERS pStubNt = (PIMAGE_NT_HEADERS)(pStubDos->e_lfanew + m_pBuf + dwFOA);
		PIMAGE_DATA_DIRECTORY pStubDir = (pStubNt->OptionalHeader.DataDirectory + 1);
		PIMAGE_IMPORT_DESCRIPTOR pStubImprotDir = (PIMAGE_IMPORT_DESCRIPTOR)(pStubDir->VirtualAddress + m_pBuf + dwFOA);
		while (pStubImprotDir->Name)
		{
			pStubImprotDir->FirstThunk += dwNewSectionRVA;
			pStubImprotDir->Name += dwNewSectionRVA;
			PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(pStubImprotDir->OriginalFirstThunk + m_pBuf + dwFOA);
			pStubImprotDir->OriginalFirstThunk += dwNewSectionRVA;
			while (pINT->u1.Ordinal)
			{
				pINT->u1.Ordinal += dwNewSectionRVA;
				pINT++;
			}
			//循环遍历模块
			pStubImprotDir++;
		}
		//exe
		PIMAGE_DOS_HEADER pExeDos = (PIMAGE_DOS_HEADER)m_pBuf;
		PIMAGE_NT_HEADERS pExeNt = (PIMAGE_NT_HEADERS)(pExeDos->e_lfanew + m_pBuf);
		PIMAGE_DATA_DIRECTORY  pExeDri = (pExeNt->OptionalHeader.DataDirectory + 1);

		//保存旧的INT
		PPACKINFO pPack = (PPACKINFO)(m_pBuf + dwFOA + m_dwPackInfoOffset);
		pPack->dwOldINTRva = pExeDri->VirtualAddress;

		//new INT
		pExeDri->Size = pStubDir->Size;
		pExeDri->VirtualAddress = pStubDir->VirtualAddress + dwNewSectionRVA;

		PIMAGE_DATA_DIRECTORY pStubIAT = (pStubNt->OptionalHeader.DataDirectory + 12);
		PIMAGE_DATA_DIRECTORY  pExeIAT = (pExeNt->OptionalHeader.DataDirectory + 12);
		pExeIAT->Size = pStubIAT->Size;
		pExeIAT->VirtualAddress = pStubIAT->VirtualAddress + dwNewSectionRVA;
}
*/


IMAGE_SECTION_HEADER* PeFileHandling::addSection(char name[8],void* pSectionData,DWORD dwSectionSize) {

	/*
	* 添加区段
	* 区段最大个数是13个
	* 添加区段的步骤:
	*  1. 修改区段个数(文件头)
	*  2. 设置区段头信息(大小, 内存中偏移,文件中的偏移, 内存属性)
	*  3. 添加区段数据
	*  4. 设置映像大小(扩展头)
	*/
	if (m_pFileBuff == nullptr)
		return nullptr;
	if (m_pFileHdr->NumberOfSections >= 13)
		return nullptr;

	IMAGE_SECTION_HEADER* pNewScn, *pLastScn;
	// 最后一个有效的区段头
	pLastScn = m_pScnHdr + m_pFileHdr->NumberOfSections - 1;
	// 新区段头
	pNewScn = m_pScnHdr + m_pFileHdr->NumberOfSections;

	// 设置名字
	memcpy((char*)pNewScn->Name, name, 8);
	// 设置大小
	pNewScn->Misc.VirtualSize = dwSectionSize;
	pNewScn->SizeOfRawData = calcAligmentSize(dwSectionSize, m_pOptHdr->FileAlignment);

	//设置内存位置
	pNewScn->VirtualAddress =
		pLastScn->VirtualAddress
		+ calcAligmentSize(pLastScn->SizeOfRawData, m_pOptHdr->SectionAlignment);

	//设置文件位置
	pNewScn->PointerToRawData =
		pLastScn->PointerToRawData + pLastScn->SizeOfRawData;

	pNewScn->Characteristics = 0xE0000060; // 默认的RWE属性

	 // 增加区段个数
	++m_pFileHdr->NumberOfSections;

	// 设置映像大小
	m_pOptHdr->SizeOfImage =pNewScn->VirtualAddress+ pNewScn->SizeOfRawData;

	// 扩充PE文件缓冲区
	char* pNewBuff = new char[m_fileSize + pNewScn->SizeOfRawData];
	memcpy(pNewBuff, m_pFileBuff, m_fileSize);
	delete[] m_pFileBuff;
	m_pFileBuff = pNewBuff;

	// 重新初始化头部
	initHeaderMember();

	// 因为已经换掉缓冲区了, 重新找到新区段
	pNewScn = m_pScnHdr + m_pFileHdr->NumberOfSections - 1;

	m_fileSize += pNewScn->SizeOfRawData;

	if (pSectionData != nullptr) {
		// 拷贝新区段的数据
		memcpy(m_pFileBuff + pNewScn->PointerToRawData,
			pSectionData,
			dwSectionSize);
	}


	// 返回最后一个有效的区段(新区段.)
	return pNewScn;
}

//参数为区段，添加数据，添加长度
void PeFileHandling::setSectioData(IMAGE_SECTION_HEADER* pScn, void* pSectionData, DWORD dwSectionSize) {
	// 拷贝新区段的数据
	memcpy(m_pFileBuff + pScn->PointerToRawData,
		pSectionData,
		dwSectionSize);
}



IMAGE_SECTION_HEADER* PeFileHandling::getSection(const char* name) {
	if (!m_pFileBuff)return NULL;
	char szName[10];
	for (int i = 0; i < m_pFileHdr->NumberOfSections; ++i) {
		memcpy(szName, m_pScnHdr[i].Name, 8);
		szName[8] = 0;
		if (strcmp(szName, name) == 0) {
			return &m_pScnHdr[i];
		}
	}
	return NULL;
}

DWORD PeFileHandling::calcAligmentSize(DWORD srcSize, DWORD aligment) {
	if (srcSize % aligment == 0)
		return srcSize;
	return (srcSize / aligment + 1) * aligment;
}

void PeFileHandling::ChangeReloc(PCHAR pBuf)
{
	// 定位到第一个重定位块
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_DATA_DIRECTORY pRelocDir = (pNt->OptionalHeader.DataDirectory + 5);
	PIMAGE_BASE_RELOCATION pReloc =(PIMAGE_BASE_RELOCATION)(pRelocDir->VirtualAddress + pBuf);


	// 开始更改重定位
	while (pReloc->SizeOfBlock != 0)
	{
		// 重定位项开始的项,将其定位到在此之前添加allen段  重定位保存的不是真正的RVA 都是是一些 0x1xxx要加上节的RVA才是真正的
		pReloc->VirtualAddress = (DWORD)(pReloc->VirtualAddress - 0x1000 + GetLastSectionRva());
		// 定位到下一个重定位块
		pReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pReloc + pReloc->SizeOfBlock);
	}

	DWORD dwRelocRva = 0;
	DWORD dwRelocSize = 0;
	DWORD dwSectionAttribute = 0;
	while (TRUE){
		if (!strcmp((char*)pSection->Name, ".reloc"))
		{
			dwRelocRva = pSection->VirtualAddress;
			dwRelocSize = pSection->SizeOfRawData;
			dwSectionAttribute = pSection->Characteristics;
			break;
		}
		pSection = pSection + 1;
	}
	//先删除原来的
	// 将stubdll的.reloc添加到PE文件的最后,返回该区段的Rva
	//DWORD RelocRva = AddSection(".nreloc", dwRelocRva + pBuf, dwRelocSize, dwSectionAttribute);
	DWORD RelocRva = (DWORD)addSection(".nreloc", dwRelocRva + pBuf, dwRelocSize);


	// 将重定位信息指向新添加的区段
	PIMAGE_DOS_HEADER pExeDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pExeNt = (PIMAGE_NT_HEADERS)(pExeDos->e_lfanew + m_pNewBuf);
	pExeNt->OptionalHeader.DataDirectory[5].VirtualAddress = RelocRva;
	pExeNt->OptionalHeader.DataDirectory[5].Size = dwRelocSize;
}



DWORD PeFileHandling::GetLastSectionRva()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + pNt->FileHeader.NumberOfSections - 1;

	return (DWORD)pLastSection;
}

void PeFileHandling::setOep(DWORD oepRva) {
	m_pOptHdr->AddressOfEntryPoint = oepRva;
}

bool PeFileHandling::saveAs(const wchar_t* pName) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(pName,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("文件不存在");
		return false;
	}
	DWORD size;
	WriteFile(hFile, m_pFileBuff, m_fileSize, &size, NULL);
	CloseHandle(hFile);

	return true;
}


SIZE_T PeFileHandling::getFileBuff() {
	return (SIZE_T)m_pFileBuff;
}

IMAGE_OPTIONAL_HEADER* PeFileHandling::getOptionHdr() {
	return m_pOptHdr;
}

IMAGE_NT_HEADERS* PeFileHandling::getNtHdr() {
	return m_pNtHdr;
}

BOOL PeFileHandling::IsPE()
{
	//判断是否为PE文件
	m_pDos = (PIMAGE_DOS_HEADER)m_pFileBuff;
	if (m_pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//不是PE文件
		MessageBox(NULL, _T("不是有效的PE文件！"), _T("提示"), MB_OK);
		delete[] m_pFileBuff;
		return FALSE;
	}
	m_pNtHdr = (PIMAGE_NT_HEADERS)(m_pFileBuff + m_pDos->e_lfanew);
	if (m_pNtHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		//不是PE文件
		MessageBox(NULL, _T("不是有效的PE文件！"), _T("提示"), MB_OK);
		delete[] m_pFileBuff;
		return FALSE;
	}
	return TRUE;
}





/*
BOOL PeFileHandling::DealwithTLS(PStubConf & pPackInfo)
{

	//PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	//PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	DWORD dwImageBase = m_pNtHdr->OptionalHeader.ImageBase;

	if (m_pNtHdr->OptionalHeader.DataDirectory[9].VirtualAddress == 0)
	{
		pPackInfo->bIsTlsUseful = FALSE;
		return FALSE;
	}
	else
	{
		pPackInfo->bIsTlsUseful = TRUE;

		g_lpTlsDir =(PIMAGE_TLS_DIRECTORY32)(RvaToOffset(m_pNtHdr->OptionalHeader.DataDirectory[9].VirtualAddress) + m_pNewBuf);
		// 获取tlsIndex的Offset
		DWORD indexOffset = RvaToOffset(g_lpTlsDir->AddressOfIndex - dwImageBase);
		// 读取设置tlsIndex的值
		pPackInfo->TlsIndex = 0;//index一般默认值为0
		if (indexOffset != -1)
		{
			pPackInfo->TlsIndex = *(DWORD*)(indexOffset + m_pNewBuf);
		}
		// 设置tls表中的信息
		m_StartOfDataAddress = g_lpTlsDir->StartAddressOfRawData;
		m_EndOfDataAddress = g_lpTlsDir->EndAddressOfRawData;
		m_CallBackFuncAddress = g_lpTlsDir->AddressOfCallBacks;

		// 将tls回调函数rva设置到共享信息结构体
		pPackInfo->TlsCallbackFuncRva = m_CallBackFuncAddress;
		return TRUE;
	}
}
*/


void PeFileHandling::initHeaderMember() {
	if (m_pFileBuff == nullptr)
		return;

	m_pDos = (IMAGE_DOS_HEADER*)m_pFileBuff;
	m_pNtHdr = (IMAGE_NT_HEADERS*)((SIZE_T)m_pDos + m_pDos->e_lfanew);
	m_pOptHdr = &m_pNtHdr->OptionalHeader;
	m_pFileHdr = &m_pNtHdr->FileHeader;
	m_pScnHdr = IMAGE_FIRST_SECTION(m_pNtHdr);
}

bool PeFileHandling::open(CString pszPath) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(pszPath, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("文件不存在");
		return false;
	}

	close();

	DWORD dwFileHig;
	m_fileSize = GetFileSize(hFile, &dwFileHig);
	m_pFileBuff = new char[m_fileSize];
	ReadFile(hFile, m_pFileBuff, m_fileSize, &dwFileHig, NULL);

	//保存一份新的
	m_pNewBuf = m_pFileBuff;

	CloseHandle(hFile);


	//判断是否为PE文件
	if (IsPE() == FALSE)
		return FALSE;


	// 初始化头部成员
	initHeaderMember();
	return true;
}
//压缩代码
void PeFileHandling::compress(){
	//1.先获取.TEXT段属性和缓冲区
	PIMAGE_SECTION_HEADER pMyText = getSection(".text");

	DWORD TextRawSize = pMyText->SizeOfRawData;
	DWORD TextPointToRD = pMyText->PointerToRawData;

	//2.利用文件偏移和文件大小获取到缓冲区
	char *TextBuf = new char[TextRawSize];
	memcpy(TextBuf, &m_pFileBuff[TextPointToRD], TextRawSize);

	//3.求压缩后的大小，目的地
	UINT nSize = aP_max_packed_size(TextRawSize);
	char *Dst = (PCHAR)GlobalAlloc(GPTR, nSize);

	//4.求工作区大小
	UINT nWorkSize = aP_workmem_size(TextRawSize);
	char* nWorkMem = (PCHAR)GlobalAlloc(GPTR, nWorkSize);

	//5.进行压缩
	UINT oldLenPack = aPsafe_pack(TextBuf, Dst, TextRawSize, nWorkMem, 0, 0);

	//6.压缩后存入目标缓冲区，并进行文件对齐
	DWORD newPackLen = calcAligmentSize(oldLenPack, m_pOptHdr->FileAlignment);

	//7.获取最终缓冲区大小
	DWORD FinalSize = m_pOptHdr->SizeOfImage - (TextRawSize - newPackLen);

	//8.更改文件总大小和text区段文件大小，其他区段的PointtoRawData

	PIMAGE_SECTION_HEADER pScnHdr;
	pScnHdr = m_pScnHdr;
	int nIndex = 0;
	for (int i = 0; i < m_pFileHdr->NumberOfSections; i++)
	{
		char Name[10] = {};
		memcpy(Name, pScnHdr[i].Name, 8);
		Name[8] = 0;
		if (!strcmp(Name, ".text"))
		{
			nIndex = i;
		}
	}
	for (; nIndex < m_pFileHdr->NumberOfSections; nIndex++)
	{
		pScnHdr[nIndex + 1].PointerToRawData -= TextRawSize;
		pScnHdr[nIndex + 1].PointerToRawData += newPackLen;
	}
	char* m_Finally = new char[FinalSize];
	memcpy(m_Finally, m_pFileBuff, TextPointToRD);
	memcpy(&m_Finally[TextPointToRD], Dst, newPackLen);
	memcpy(&m_Finally[TextPointToRD + newPackLen], &m_pFileBuff[TextPointToRD + TextRawSize],
		m_fileSize - TextRawSize - TextPointToRD);

	//更改text段大小， 释放掉多余缓冲区
	delete[] m_pFileBuff;
	m_pFileBuff = m_Finally;
	m_fileSize = FinalSize;
	delete[] TextBuf;
}



/*
void CallTls()
{
// 将tls回调函数表指针设置回去
//PIMAGE_TLS_DIRECTORY pTlsDir =
//	(PIMAGE_TLS_DIRECTORY)(lpNtHeader->OptionalHeader.DataDirectory[9].VirtualAddress + g_dwImageBase);


//g_lpTlsDir =(PIMAGE_TLS_DIRECTORY32)(RvaToOffset(pNt->OptionalHeader.DataDirectory[9].VirtualAddress) + m_pNewBuf);


//解压完数据看是否有TLS函数 如果有 则调用
if (g_lpTlsDir != NULL){
HMODULE hModule = GetModuleHandle(NULL);
PIMAGE_TLS_CALLBACK* lptlsFun = (PIMAGE_TLS_CALLBACK*)g_lpTlsDir->AddressOfCallBacks;
while (lptlsFun[0] != NULL){
lptlsFun[0](hModule, DLL_PROCESS_ATTACH, NULL);
lptlsFun++;
}
}
}
*/


/*
void RecoverIAT()
{
HMODULE hModule = GetModuleHandle(NULL);

IMAGE_DOS_HEADER* lpDosHeader = (IMAGE_DOS_HEADER*)hModule;
IMAGE_NT_HEADERS* lpNtHeader = (IMAGE_NT_HEADERS*)(lpDosHeader->e_lfanew + (DWORD)hModule);
LPVOID lpImageBase = (LPVOID)lpNtHeader->OptionalHeader.ImageBase;


//导入表处理
IMAGE_IMPORT_DESCRIPTOR* lpImportTable = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)lpImageBase + g_dwOldImp);

int DllNameOffset = 0;
int ThunkRVA = 0;
HMODULE hDll = NULL;
int* lpIAT = NULL;

while (lpImportTable->Name)
{
DllNameOffset = lpImportTable->Name + (DWORD)lpImageBase;
hDll = LoadLibrary((LPCWSTR)DllNameOffset);

if (lpImportTable->FirstThunk == 0)
{
lpImportTable++;
continue;
}
lpIAT = (int*)(lpImportTable->FirstThunk + (DWORD)lpImageBase);

if (lpImportTable->OriginalFirstThunk == 0)
{
ThunkRVA = lpImportTable->FirstThunk;
}
else
{
ThunkRVA = lpImportTable->OriginalFirstThunk;
}
IMAGE_THUNK_DATA* lpThunkData = (IMAGE_THUNK_DATA*)((DWORD)lpImageBase + ThunkRVA);
int funAddress = 0;
int FunName = 0;
while (lpThunkData->u1.Ordinal != 0)
{
//名字导出
if ((lpThunkData->u1.Ordinal & 0x80000000) == 0)
{
IMAGE_IMPORT_BY_NAME* lpImprotName = (IMAGE_IMPORT_BY_NAME*)((DWORD)lpImageBase + lpThunkData->u1.Ordinal);
FunName = (int)&(lpImprotName->Name);
}
else
{
FunName = lpThunkData->u1.Ordinal & 0xffff;
}

int funAddress = (int)GetProcAddress(hDll, (char*)FunName);
DWORD dwOld;
VirtualProtect(lpIAT, 4, PAGE_EXECUTE_READWRITE, &dwOld);
*(lpIAT) = funAddress;
VirtualProtect(lpIAT, 4, dwOld, NULL);
lpIAT++;

lpThunkData++;

}
lpImportTable++;
}

}

*/



//
//void FixIAT()
//{
//	/* 获取INT的地址 */
//	//DWORD dwRva = g_PackInfo.dwOldINTRva;
//	DWORD dwRva = 0;
//
//	//HMODULE hBase = g_GetModuleHandleA(0);
//	HMODULE hBase = apis.pfnGetModuleHandleA(0);
//
//	PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hBase + dwRva);
//	/*修复导入表*/
//	while (pImp->Name) {
//		/*导入DLL*/
//		PCHAR pDllName = (PCHAR)((DWORD)hBase + pImp->Name);
//		//HMODULE hDll = g_LoadLibraryA(pDllName);
//		HMODULE hDll = apis.pfnLoadLibraryA(pDllName);
//
//		/*获取名称数组起始地址和地址数组起始地址*/
//		PIMAGE_THUNK_DATA pArrFunName = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->OriginalFirstThunk);
//		PIMAGE_THUNK_DATA pArrFunAddr = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->FirstThunk);
//		/*根据名字/序号获取函数地址，存入对应的地址数组内*/
//		DWORD dwCount = 0;
//		while (pArrFunName->u1.Ordinal) {
//			/*该变量用于存放找到的函数地址*/
//			DWORD dwFunAddr = 0;
//			if (IMAGE_SNAP_BY_ORDINAL(pArrFunName->u1.Ordinal)) {
//				//dwFunAddr = (DWORD)g_GetProcAddress(hDll, (CHAR*)(pArrFunName->u1.Ordinal /*& 0x0ffff*/));
//				dwFunAddr = (DWORD)apis.pfnGetProcAddress(hDll, (CHAR*)(pArrFunName->u1.Ordinal));
//			}
//			else {
//				/* 找到该函数名称*/
//				PIMAGE_IMPORT_BY_NAME pStcName = (PIMAGE_IMPORT_BY_NAME)
//					((DWORD)hBase + pArrFunName->u1.Function);
//				//dwFunAddr = (DWORD)g_GetProcAddress(hDll, pStcName->Name);
//				dwFunAddr = (DWORD)apis.pfnGetProcAddress(hDll, pStcName->Name);
//
//			}
//			/*确保可写*/
//			DWORD dwOldProtect = 0;
//			//g_VirtualProtect(&pArrFunAddr[dwCount], 4, PAGE_READWRITE, &dwOldProtect);
//			apis.pfnVirtualProtect(&pArrFunAddr[dwCount], 4, PAGE_READWRITE, &dwOldProtect);
//
//			/*将函数地址放入IAT数组中对应成员内*/
//			pArrFunAddr[dwCount].u1.AddressOfData = dwFunAddr;
//			//g_VirtualProtect(&pArrFunAddr[dwCount], 4, dwOldProtect, &dwOldProtect);
//			apis.pfnVirtualProtect(&pArrFunAddr[dwCount], 4, dwOldProtect, &dwOldProtect);
//
//			/*下一个函数*/
//			pArrFunName++;
//			dwCount++;
//		}
//		/*下一个DLL*/
//		pImp++;
//	}
//}




//void FixSrcReloc()
//{
//		// 找到原重定位表信息的地址
//		//HMODULE hBase = g_GetModuleHandleA(0);
//	HMODULE hBase = apis.pfnGetModuleHandleA(0);
//		//默认加载基址
//		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hBase;
//		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hBase + pDos->e_lfanew);
//		// 减去默认加载基址
//		DWORD dwImageBase = 0x400000;
//		//是否有重定位信息
//		if (!g_stubConf.dwOldRelocRva || !g_stubConf.dwOldRelocSize) {
//			return;
//		}
//		//找到要重定位的数据
//		PIMAGE_BASE_RELOCATION  pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)hBase + g_stubConf.dwOldRelocRva);
//		DWORD dwCount = 0;
//		while (pRelocAddr->VirtualAddress && dwCount < g_stubConf.dwOldRelocSize) {
//			// 重定位块数组的起始地址
//			PRELOCTYPE pOffSetArr = (PRELOCTYPE)(pRelocAddr + 1);
//			// 数组成员个数
//			DWORD dwCount = (pRelocAddr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCTYPE);
//			for (DWORD i = 0; i < dwCount; ++i) {
//				if (pOffSetArr[i].type == 3) {
//					//要重定位的数据的RVA
//					DWORD dwOffset = pOffSetArr[i].offset + pRelocAddr->VirtualAddress;
//					//要重定位的数据的VA
//					PDWORD pAddr = (PDWORD)((DWORD)hBase + dwOffset);
//					//保证可写
//					DWORD dwOldProtect = 0;
//					//if (!g_VirtualProtect(pAddr, 4, PAGE_READWRITE, &dwOldProtect)) return;
//					if (!apis.pfnVirtualProtect(pAddr, 4, PAGE_READWRITE, &dwOldProtect)) return;
//
//
//					/*修复该值
//					修复后的值 = 修复前的值 - dwImageBase + hBase*/
//					*pAddr = *pAddr - dwImageBase + (DWORD)hBase;
//					//if (!g_VirtualProtect(pAddr, 4, dwOldProtect, &dwOldProtect)) return;
//					if (!apis.pfnVirtualProtect(pAddr, 4, dwOldProtect, &dwOldProtect)) return;
//
//				}
//			}
//			// 已重定位数据大小
//			dwCount += pRelocAddr->SizeOfBlock;
//			// 定位到下一个区块
//			pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocAddr + pRelocAddr->SizeOfBlock);
//		}
//}
//
//
//void FixReloc()
//{
//	//以下是重定位
//	DWORD *tmp;
//	DWORD g_dwImageBase = (DWORD)apis.pfnGetModuleHandleA(NULL);
//	if (g_stubConf.RelocRva)  //如果没有重定位表跳过
//	{
//		DWORD relocation = (DWORD)g_dwImageBase - g_stubConf.ImageBase;
//		IMAGE_BASE_RELOCATION  *relocationAddress = (IMAGE_BASE_RELOCATION*)(g_stubConf.RelocRva + (DWORD)g_dwImageBase);
//
//		while (relocationAddress->VirtualAddress != 0)
//		{
//			LPVOID rva = (LPVOID)((DWORD)g_dwImageBase + relocationAddress->VirtualAddress);
//			DWORD BlockNum = (relocationAddress->SizeOfBlock - 8) / 2;
//			if (BlockNum == 0) break;
//			WORD *Offset = (WORD *)((DWORD)relocationAddress + 8);
//			for (int i = 0; i < (int)BlockNum; i++)
//			{
//				if ((Offset[i] & 0xF000) != 0x3000) continue;
//				tmp = (DWORD*)((Offset[i] & 0xFFF) + (DWORD)rva);
//				*tmp = (*tmp) + relocation;
//			}
//			relocationAddress = (IMAGE_BASE_RELOCATION*)((DWORD)relocationAddress + relocationAddress->SizeOfBlock);
//		}
//	}
//}

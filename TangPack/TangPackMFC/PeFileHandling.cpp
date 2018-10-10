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
		// ����ŷ�ʽ����
		WORD ord = (SIZE_T)pszName & 0xFFFF;
		DWORD* pEat = (DWORD*)(RvaToOffset(pExpDir->AddressOfFunctions) + (SIZE_T)m_pFileBuff);
		return (pEat[ord - pExpDir->Base]);
	}

	// �������Ʊ�, �ҵ�����
	PDWORD pEnt = (PDWORD)(RvaToOffset(pExpDir->AddressOfNames) + (SIZE_T)m_pFileBuff);
	char* pName = NULL;
	for (DWORD i = 0; i < pExpDir->NumberOfNames; ++i) {
		pName = (char*)(RvaToOffset(pEnt[i]) + (SIZE_T)m_pFileBuff);
		if (strcmp(pszName, pName) == 0) {
			// �ҵ��˺���
			WORD* pEot = (WORD*)(RvaToOffset(pExpDir->AddressOfNameOrdinals) + (SIZE_T)m_pFileBuff);
			// ����ű���ȡ����ַ����±�
			DWORD index = pEot[i];
			DWORD* pEat = (DWORD*)(RvaToOffset(pExpDir->AddressOfFunctions) + (SIZE_T)m_pFileBuff);
			return pEat[index];
		}
	}
	return NULL;
}

void PeFileHandling::fixStubRva(DWORD oldImageBase,DWORD newImageBase,DWORD oldSectionRva,DWORD newSectionRva) {

	if (m_pFileBuff == nullptr)return;


	//1.��ȡ���ӿ�PE�ļ����ض�λĿ¼��ָ����Ϣ
	//PIMAGE_DATA_DIRECTORY pPERelocDir =
	//	&(m_pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);


	//PIMAGE_DOS_HEADER		pShellDosHeader = (PIMAGE_DOS_HEADER)pShellBuf;
//	PIMAGE_NT_HEADERS		pShellNtHeader = (PIMAGE_NT_HEADERS)(pShellBuf + pShellDosHeader->e_lfanew);
	//PIMAGE_DATA_DIRECTORY	pShellRelocDir =
	//	&(pShellNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);



	//
	// �޸�stub���ֵ��ض�λ����
	// ��ַ= ���ػ�ַ + ����RVA + ����ƫ��

	//��ȡShell���ض�λ��ָ����Ϣ
	IMAGE_BASE_RELOCATION* pRelTab;
	pRelTab = (IMAGE_BASE_RELOCATION*)
		(RvaToOffset(m_pOptHdr->DataDirectory[5].VirtualAddress) + getFileBuff());

	/*!
	* \brief �ض�λ���ƫ�ƽṹ
	*/
	struct TypeOffset {
		WORD Offset : 12;  // (1) ��СΪ12Bit���ض�λƫ��
		WORD Type : 4;    // (2) ��СΪ4Bit���ض�λ��Ϣ����ֵ
	};


	//dllͨ��LoadLibrary���صģ�ϵͳ��������һ���ض�λ
	//��Shell.dll���ض�λ��Ϣ�ָ���ϵͳû����֮ǰ����д�뱻�ӿ��ļ���ĩβ
	while (pRelTab->SizeOfBlock != 0) {
		TypeOffset* tofs;
		DWORD count;
		count = (pRelTab->SizeOfBlock - 8) / 2;

		tofs = (TypeOffset*)(pRelTab + 1);
		for (DWORD i = 0; i < count; ++i) {
			if (tofs[i].Type == 3) {

				SIZE_T* pFixVa = (SIZE_T*)(RvaToOffset(tofs[i].Offset + pRelTab->VirtualAddress) + getFileBuff());
				// �滻���ػ�ַ
				*pFixVa -= oldImageBase; // Ĭ�ϼ��ػ�ַ
				*pFixVa += newImageBase; // �µļ��ػ�ַ
										 // �滻����RVA
				*pFixVa -= oldSectionRva; // �ɵ����ζ���RVA
				*pFixVa += newSectionRva; // �µ����ζ���RVA
			}
		}

		// �ҵ���һ���ض�λ��
		pRelTab = (IMAGE_BASE_RELOCATION*)((SIZE_T)pRelTab + pRelTab->SizeOfBlock);
	}


	//�޸�PE�ض�λĿ¼ָ�룬ָ��Shell���ض�λ����Ϣ
	//pPERelocDir->Size = pRelTab->Size;
	//pPERelocDir->VirtualAddress = pShellRelocDir->VirtualAddress + m_dwImageSize;

}


/*
void PeFileHandling::FixINT(PCHAR pBuf)
{
		//�ҵ������ε���ʼλ��
		PIMAGE_DOS_HEADER pDosNew = (PIMAGE_DOS_HEADER)m_pBuf;
		PIMAGE_NT_HEADERS pNtNew = (PIMAGE_NT_HEADERS)(pDosNew->e_lfanew + m_pBuf);
		//eason��
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
			//ѭ������ģ��
			pStubImprotDir++;
		}
		//exe
		PIMAGE_DOS_HEADER pExeDos = (PIMAGE_DOS_HEADER)m_pBuf;
		PIMAGE_NT_HEADERS pExeNt = (PIMAGE_NT_HEADERS)(pExeDos->e_lfanew + m_pBuf);
		PIMAGE_DATA_DIRECTORY  pExeDri = (pExeNt->OptionalHeader.DataDirectory + 1);

		//����ɵ�INT
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
	* �������
	* ������������13��
	* ������εĲ���:
	*  1. �޸����θ���(�ļ�ͷ)
	*  2. ��������ͷ��Ϣ(��С, �ڴ���ƫ��,�ļ��е�ƫ��, �ڴ�����)
	*  3. �����������
	*  4. ����ӳ���С(��չͷ)
	*/
	if (m_pFileBuff == nullptr)
		return nullptr;
	if (m_pFileHdr->NumberOfSections >= 13)
		return nullptr;

	IMAGE_SECTION_HEADER* pNewScn, *pLastScn;
	// ���һ����Ч������ͷ
	pLastScn = m_pScnHdr + m_pFileHdr->NumberOfSections - 1;
	// ������ͷ
	pNewScn = m_pScnHdr + m_pFileHdr->NumberOfSections;

	// ��������
	memcpy((char*)pNewScn->Name, name, 8);
	// ���ô�С
	pNewScn->Misc.VirtualSize = dwSectionSize;
	pNewScn->SizeOfRawData = calcAligmentSize(dwSectionSize, m_pOptHdr->FileAlignment);

	//�����ڴ�λ��
	pNewScn->VirtualAddress =
		pLastScn->VirtualAddress
		+ calcAligmentSize(pLastScn->SizeOfRawData, m_pOptHdr->SectionAlignment);

	//�����ļ�λ��
	pNewScn->PointerToRawData =
		pLastScn->PointerToRawData + pLastScn->SizeOfRawData;

	pNewScn->Characteristics = 0xE0000060; // Ĭ�ϵ�RWE����

	 // �������θ���
	++m_pFileHdr->NumberOfSections;

	// ����ӳ���С
	m_pOptHdr->SizeOfImage =pNewScn->VirtualAddress+ pNewScn->SizeOfRawData;

	// ����PE�ļ�������
	char* pNewBuff = new char[m_fileSize + pNewScn->SizeOfRawData];
	memcpy(pNewBuff, m_pFileBuff, m_fileSize);
	delete[] m_pFileBuff;
	m_pFileBuff = pNewBuff;

	// ���³�ʼ��ͷ��
	initHeaderMember();

	// ��Ϊ�Ѿ�������������, �����ҵ�������
	pNewScn = m_pScnHdr + m_pFileHdr->NumberOfSections - 1;

	m_fileSize += pNewScn->SizeOfRawData;

	if (pSectionData != nullptr) {
		// ���������ε�����
		memcpy(m_pFileBuff + pNewScn->PointerToRawData,
			pSectionData,
			dwSectionSize);
	}


	// �������һ����Ч������(������.)
	return pNewScn;
}

//����Ϊ���Σ�������ݣ���ӳ���
void PeFileHandling::setSectioData(IMAGE_SECTION_HEADER* pScn, void* pSectionData, DWORD dwSectionSize) {
	// ���������ε�����
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
	// ��λ����һ���ض�λ��
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_DATA_DIRECTORY pRelocDir = (pNt->OptionalHeader.DataDirectory + 5);
	PIMAGE_BASE_RELOCATION pReloc =(PIMAGE_BASE_RELOCATION)(pRelocDir->VirtualAddress + pBuf);


	// ��ʼ�����ض�λ
	while (pReloc->SizeOfBlock != 0)
	{
		// �ض�λ�ʼ����,���䶨λ���ڴ�֮ǰ���allen��  �ض�λ����Ĳ���������RVA ������һЩ 0x1xxxҪ���Ͻڵ�RVA����������
		pReloc->VirtualAddress = (DWORD)(pReloc->VirtualAddress - 0x1000 + GetLastSectionRva());
		// ��λ����һ���ض�λ��
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
	//��ɾ��ԭ����
	// ��stubdll��.reloc��ӵ�PE�ļ������,���ظ����ε�Rva
	//DWORD RelocRva = AddSection(".nreloc", dwRelocRva + pBuf, dwRelocSize, dwSectionAttribute);
	DWORD RelocRva = (DWORD)addSection(".nreloc", dwRelocRva + pBuf, dwRelocSize);


	// ���ض�λ��Ϣָ������ӵ�����
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
		printf("�ļ�������");
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
	//�ж��Ƿ�ΪPE�ļ�
	m_pDos = (PIMAGE_DOS_HEADER)m_pFileBuff;
	if (m_pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//����PE�ļ�
		MessageBox(NULL, _T("������Ч��PE�ļ���"), _T("��ʾ"), MB_OK);
		delete[] m_pFileBuff;
		return FALSE;
	}
	m_pNtHdr = (PIMAGE_NT_HEADERS)(m_pFileBuff + m_pDos->e_lfanew);
	if (m_pNtHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		//����PE�ļ�
		MessageBox(NULL, _T("������Ч��PE�ļ���"), _T("��ʾ"), MB_OK);
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
		// ��ȡtlsIndex��Offset
		DWORD indexOffset = RvaToOffset(g_lpTlsDir->AddressOfIndex - dwImageBase);
		// ��ȡ����tlsIndex��ֵ
		pPackInfo->TlsIndex = 0;//indexһ��Ĭ��ֵΪ0
		if (indexOffset != -1)
		{
			pPackInfo->TlsIndex = *(DWORD*)(indexOffset + m_pNewBuf);
		}
		// ����tls���е���Ϣ
		m_StartOfDataAddress = g_lpTlsDir->StartAddressOfRawData;
		m_EndOfDataAddress = g_lpTlsDir->EndAddressOfRawData;
		m_CallBackFuncAddress = g_lpTlsDir->AddressOfCallBacks;

		// ��tls�ص�����rva���õ�������Ϣ�ṹ��
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
		printf("�ļ�������");
		return false;
	}

	close();

	DWORD dwFileHig;
	m_fileSize = GetFileSize(hFile, &dwFileHig);
	m_pFileBuff = new char[m_fileSize];
	ReadFile(hFile, m_pFileBuff, m_fileSize, &dwFileHig, NULL);

	//����һ���µ�
	m_pNewBuf = m_pFileBuff;

	CloseHandle(hFile);


	//�ж��Ƿ�ΪPE�ļ�
	if (IsPE() == FALSE)
		return FALSE;


	// ��ʼ��ͷ����Ա
	initHeaderMember();
	return true;
}
//ѹ������
void PeFileHandling::compress(){
	//1.�Ȼ�ȡ.TEXT�����Ժͻ�����
	PIMAGE_SECTION_HEADER pMyText = getSection(".text");

	DWORD TextRawSize = pMyText->SizeOfRawData;
	DWORD TextPointToRD = pMyText->PointerToRawData;

	//2.�����ļ�ƫ�ƺ��ļ���С��ȡ��������
	char *TextBuf = new char[TextRawSize];
	memcpy(TextBuf, &m_pFileBuff[TextPointToRD], TextRawSize);

	//3.��ѹ����Ĵ�С��Ŀ�ĵ�
	UINT nSize = aP_max_packed_size(TextRawSize);
	char *Dst = (PCHAR)GlobalAlloc(GPTR, nSize);

	//4.��������С
	UINT nWorkSize = aP_workmem_size(TextRawSize);
	char* nWorkMem = (PCHAR)GlobalAlloc(GPTR, nWorkSize);

	//5.����ѹ��
	UINT oldLenPack = aPsafe_pack(TextBuf, Dst, TextRawSize, nWorkMem, 0, 0);

	//6.ѹ�������Ŀ�껺�������������ļ�����
	DWORD newPackLen = calcAligmentSize(oldLenPack, m_pOptHdr->FileAlignment);

	//7.��ȡ���ջ�������С
	DWORD FinalSize = m_pOptHdr->SizeOfImage - (TextRawSize - newPackLen);

	//8.�����ļ��ܴ�С��text�����ļ���С���������ε�PointtoRawData

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

	//����text�δ�С�� �ͷŵ����໺����
	delete[] m_pFileBuff;
	m_pFileBuff = m_Finally;
	m_fileSize = FinalSize;
	delete[] TextBuf;
}



/*
void CallTls()
{
// ��tls�ص�������ָ�����û�ȥ
//PIMAGE_TLS_DIRECTORY pTlsDir =
//	(PIMAGE_TLS_DIRECTORY)(lpNtHeader->OptionalHeader.DataDirectory[9].VirtualAddress + g_dwImageBase);


//g_lpTlsDir =(PIMAGE_TLS_DIRECTORY32)(RvaToOffset(pNt->OptionalHeader.DataDirectory[9].VirtualAddress) + m_pNewBuf);


//��ѹ�����ݿ��Ƿ���TLS���� ����� �����
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


//�������
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
//���ֵ���
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
//	/* ��ȡINT�ĵ�ַ */
//	//DWORD dwRva = g_PackInfo.dwOldINTRva;
//	DWORD dwRva = 0;
//
//	//HMODULE hBase = g_GetModuleHandleA(0);
//	HMODULE hBase = apis.pfnGetModuleHandleA(0);
//
//	PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hBase + dwRva);
//	/*�޸������*/
//	while (pImp->Name) {
//		/*����DLL*/
//		PCHAR pDllName = (PCHAR)((DWORD)hBase + pImp->Name);
//		//HMODULE hDll = g_LoadLibraryA(pDllName);
//		HMODULE hDll = apis.pfnLoadLibraryA(pDllName);
//
//		/*��ȡ����������ʼ��ַ�͵�ַ������ʼ��ַ*/
//		PIMAGE_THUNK_DATA pArrFunName = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->OriginalFirstThunk);
//		PIMAGE_THUNK_DATA pArrFunAddr = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->FirstThunk);
//		/*��������/��Ż�ȡ������ַ�������Ӧ�ĵ�ַ������*/
//		DWORD dwCount = 0;
//		while (pArrFunName->u1.Ordinal) {
//			/*�ñ������ڴ���ҵ��ĺ�����ַ*/
//			DWORD dwFunAddr = 0;
//			if (IMAGE_SNAP_BY_ORDINAL(pArrFunName->u1.Ordinal)) {
//				//dwFunAddr = (DWORD)g_GetProcAddress(hDll, (CHAR*)(pArrFunName->u1.Ordinal /*& 0x0ffff*/));
//				dwFunAddr = (DWORD)apis.pfnGetProcAddress(hDll, (CHAR*)(pArrFunName->u1.Ordinal));
//			}
//			else {
//				/* �ҵ��ú�������*/
//				PIMAGE_IMPORT_BY_NAME pStcName = (PIMAGE_IMPORT_BY_NAME)
//					((DWORD)hBase + pArrFunName->u1.Function);
//				//dwFunAddr = (DWORD)g_GetProcAddress(hDll, pStcName->Name);
//				dwFunAddr = (DWORD)apis.pfnGetProcAddress(hDll, pStcName->Name);
//
//			}
//			/*ȷ����д*/
//			DWORD dwOldProtect = 0;
//			//g_VirtualProtect(&pArrFunAddr[dwCount], 4, PAGE_READWRITE, &dwOldProtect);
//			apis.pfnVirtualProtect(&pArrFunAddr[dwCount], 4, PAGE_READWRITE, &dwOldProtect);
//
//			/*��������ַ����IAT�����ж�Ӧ��Ա��*/
//			pArrFunAddr[dwCount].u1.AddressOfData = dwFunAddr;
//			//g_VirtualProtect(&pArrFunAddr[dwCount], 4, dwOldProtect, &dwOldProtect);
//			apis.pfnVirtualProtect(&pArrFunAddr[dwCount], 4, dwOldProtect, &dwOldProtect);
//
//			/*��һ������*/
//			pArrFunName++;
//			dwCount++;
//		}
//		/*��һ��DLL*/
//		pImp++;
//	}
//}




//void FixSrcReloc()
//{
//		// �ҵ�ԭ�ض�λ����Ϣ�ĵ�ַ
//		//HMODULE hBase = g_GetModuleHandleA(0);
//	HMODULE hBase = apis.pfnGetModuleHandleA(0);
//		//Ĭ�ϼ��ػ�ַ
//		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hBase;
//		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hBase + pDos->e_lfanew);
//		// ��ȥĬ�ϼ��ػ�ַ
//		DWORD dwImageBase = 0x400000;
//		//�Ƿ����ض�λ��Ϣ
//		if (!g_stubConf.dwOldRelocRva || !g_stubConf.dwOldRelocSize) {
//			return;
//		}
//		//�ҵ�Ҫ�ض�λ������
//		PIMAGE_BASE_RELOCATION  pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)hBase + g_stubConf.dwOldRelocRva);
//		DWORD dwCount = 0;
//		while (pRelocAddr->VirtualAddress && dwCount < g_stubConf.dwOldRelocSize) {
//			// �ض�λ���������ʼ��ַ
//			PRELOCTYPE pOffSetArr = (PRELOCTYPE)(pRelocAddr + 1);
//			// �����Ա����
//			DWORD dwCount = (pRelocAddr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCTYPE);
//			for (DWORD i = 0; i < dwCount; ++i) {
//				if (pOffSetArr[i].type == 3) {
//					//Ҫ�ض�λ�����ݵ�RVA
//					DWORD dwOffset = pOffSetArr[i].offset + pRelocAddr->VirtualAddress;
//					//Ҫ�ض�λ�����ݵ�VA
//					PDWORD pAddr = (PDWORD)((DWORD)hBase + dwOffset);
//					//��֤��д
//					DWORD dwOldProtect = 0;
//					//if (!g_VirtualProtect(pAddr, 4, PAGE_READWRITE, &dwOldProtect)) return;
//					if (!apis.pfnVirtualProtect(pAddr, 4, PAGE_READWRITE, &dwOldProtect)) return;
//
//
//					/*�޸���ֵ
//					�޸����ֵ = �޸�ǰ��ֵ - dwImageBase + hBase*/
//					*pAddr = *pAddr - dwImageBase + (DWORD)hBase;
//					//if (!g_VirtualProtect(pAddr, 4, dwOldProtect, &dwOldProtect)) return;
//					if (!apis.pfnVirtualProtect(pAddr, 4, dwOldProtect, &dwOldProtect)) return;
//
//				}
//			}
//			// ���ض�λ���ݴ�С
//			dwCount += pRelocAddr->SizeOfBlock;
//			// ��λ����һ������
//			pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocAddr + pRelocAddr->SizeOfBlock);
//		}
//}
//
//
//void FixReloc()
//{
//	//�������ض�λ
//	DWORD *tmp;
//	DWORD g_dwImageBase = (DWORD)apis.pfnGetModuleHandleA(NULL);
//	if (g_stubConf.RelocRva)  //���û���ض�λ������
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

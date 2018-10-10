// stub.cpp : ���� DLL Ӧ�ó���ĵ���������
//
#include "stdafx.h"
#include "stub.h"

#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text") 
#pragma comment(linker, "/section:.text,RWE")


//
// һ���������Ľṹ�����
// ���汣���ű��ӿǳ������Ϣ,���ļ�ͷ,��չͷ,
// ���α��.
// ��������ṹ���Ѿ�������, ���,����ֱ��ͨ��
// �������������õ���.
STUB_API StubConf g_stubConf = { 0xAAAAAAAA };


//API����ָ��ԭ��
typedef BOOL(WINAPI* PFNVirtualProtect)(LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect);


typedef LPVOID(WINAPI *PFNGetProcAddress)(_In_ HMODULE hModule,_In_ LPCSTR lpProcName);


typedef  HMODULE(WINAPI*PFNLoadLibraryA)(const char*);


typedef struct APIS {
	PFNVirtualProtect pfnVirtualProtect;
	PFNGetProcAddress pfnGetProcAddress;
	PFNLoadLibraryA   pfnLoadLibraryA;
	PFNVirtualAlloc pfnVirtualAlloc;
	PFNExitProcess pfnExitProcess;
	PFNMessageBox pfnMessageBox;
	PFNLGetModuleHandleA pfnGetModuleHandleA;

	PFNIsDebuggerPresent pfnIsDebuggerPresent;
	PFNAddVectoredExceptionHandler pfnAddVectoredExceptionHandler;
	PFNRemoveVectoredExceptionHandler pfnRemoveVectoredExceptionHandler;

	PFNaPsafe_depack pfnaPsafe_depack;
	PFNGlobalAlloc pfnGlobalAlloc;
	PFNaPsafe_get_orig_size pfnaPsafe_get_orig_size;
	//------------------------------sdk---
	PFNGetDlgItem        pfnGetDlgItem;
	PFNGetWindowText     pfnGetWindowText;
	PFNDestroyWindow     pfnDestroyWindow;
	PFNGetClientRect     pfnGetClientRect;
	PFNPostQuitMessage   pfnPostQuitMessage;
	PFNDefWindowProc     pfnDefWindowProc;
	PFNLoadIcon          pfnLoadIcon;
	PFNLoadCursor        pfnLoadCursor;
	PFNRegisterClass     pfnRegisterClass;
	PFNPFNCreateWindow   pfnCreateWindow;
	PFNShowWindow        pfnShowWindow;
	PFNGetMessage        pfnGetMessage;
	PFNTranslateMessage  pfnTranslateMessage;
	PFNDispatchMessage   pfnDispatchMessage;
}APIS;


/// ����API��ȫ�ֱ���
APIS apis;


void FixReloc()
{
	//�������ض�λ
	DWORD *tmp;
	DWORD g_dwImageBase = (DWORD)apis.pfnGetModuleHandleA(NULL);
	if (g_stubConf.RelocRva)  //���û���ض�λ���ʾ�����ض�λ�������ض�λ����
	{
		DWORD relocation = (DWORD)g_dwImageBase - g_stubConf.ImageBase;
		IMAGE_BASE_RELOCATION  *relocationAddress = (IMAGE_BASE_RELOCATION*)(g_stubConf.RelocRva + (DWORD)g_dwImageBase);

		while (relocationAddress->VirtualAddress != 0)
		{
			LPVOID rva = (LPVOID)((DWORD)g_dwImageBase + relocationAddress->VirtualAddress);
			DWORD BlockNum = (relocationAddress->SizeOfBlock - 8) / 2;
			if (BlockNum == 0) break;
			WORD *Offset = (WORD *)((DWORD)relocationAddress + 8);
			for (int i = 0; i < (int)BlockNum; i++)
			{
				if ((Offset[i] & 0xF000) != 0x3000) continue;
				tmp = (DWORD*)((Offset[i] & 0xFFF) + (DWORD)rva);
				*tmp = (*tmp) + relocation;
			}
			relocationAddress = (IMAGE_BASE_RELOCATION*)((DWORD)relocationAddress + relocationAddress->SizeOfBlock);
		}
	}
}

//�Զ���Ƚ��ַ������� խ�ַ���wchar_t����unsigned char
int CmpStr(const wchar_t * src, const wchar_t * dst)
{
	int ret = 0;
	while (!(ret = *(wchar_t *)src - *(wchar_t *)dst) && *dst)
		++src, ++dst;
	if (ret < 0)
		ret = -1;
	else if (ret > 0)
		ret = 1;
	return(ret);
}

void decrypt() {
	char* pSrc = (char*)(g_stubConf.dwTextSectionRva + g_stubConf.ntheader.OptionalHeader.ImageBase);

	DWORD oldPro;
	apis.pfnVirtualProtect(pSrc, g_stubConf.dwTextSectionSize, PAGE_READWRITE, &oldPro);

	//for (DWORD i = 0; i < g_stubConf.dwTextSectionSize; ++i) {
	//	pSrc[i] ^= g_stubConf.key;
	//}


	for (signed int d = (g_stubConf.dwTextSectionSize - 1); d >= 0; --d)
	{
		g_stubConf.key = pSrc[d] ^ g_stubConf.key;
		pSrc[d] = pSrc[d] - g_stubConf.key;
	}


	apis.pfnVirtualProtect(pSrc, g_stubConf.dwTextSectionSize, oldPro, &oldPro);
}

LPVOID MyGetProcAddress(HMODULE hModule, const char* pszName) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (SIZE_T)pDos);
	PIMAGE_EXPORT_DIRECTORY pExpDir;

	pExpDir = (PIMAGE_EXPORT_DIRECTORY)
		(pNt->OptionalHeader.DataDirectory[0].VirtualAddress + (SIZE_T)hModule);

	if ((((SIZE_T)pszName >> 16) & 0xFFFF) == 0) {
		// ����ŷ�ʽ����
		WORD ord = (SIZE_T)pszName & 0xFFFF;
		DWORD* pEat = (DWORD*)(pExpDir->AddressOfFunctions + (SIZE_T)hModule);
		return (LPVOID)(pEat[ord - pExpDir->Base] + (SIZE_T)hModule);
	}


	// �������Ʊ�, �ҵ�����
	PDWORD pEnt = (PDWORD)(pExpDir->AddressOfNames + (SIZE_T)hModule);
	char* pName = NULL;
	for (DWORD i = 0; i < pExpDir->NumberOfNames; ++i) {
		pName = (char*)(pEnt[i] + (SIZE_T)hModule);
		if (strcmp(pszName, pName) == 0) {
			// �ҵ��˺���
			WORD* pEot = (WORD*)(pExpDir->AddressOfNameOrdinals + (SIZE_T)hModule);
			// ����ű���ȡ����ַ����±�
			DWORD index = pEot[i];
			DWORD* pEat = (DWORD*)(pExpDir->AddressOfFunctions + (SIZE_T)hModule);
			SIZE_T address = pEat[index] + (SIZE_T)hModule;
			return (LPVOID)address;
		}
	}
	return NULL;
}


void GetAPIs() {
	// 1. �ҵ�kernel32�ļ��ػ�ַ
	// �ҵ�GetProcAddress��LoadLibrary�����ĵ�ַ
	HMODULE hKernel32;
	_asm {
		mov         eax, dword ptr fs : [30h]
		mov         eax, dword ptr[eax + 0Ch]
		mov         eax, dword ptr[eax + 0Ch]
		mov         eax, dword ptr[eax]
		mov         eax, dword ptr[eax]
		mov         eax, dword ptr[eax + 18h]
		mov hKernel32, eax;
	}
	//
	// ��ȡҪ�õ��ĺ�����ַ
	// ��kernel32�л�ȡ����
	apis.pfnGetProcAddress = (PFNGetProcAddress)MyGetProcAddress(hKernel32, "GetProcAddress");
	apis.pfnLoadLibraryA = (PFNLoadLibraryA)apis.pfnGetProcAddress(hKernel32, "LoadLibraryA");
	apis.pfnVirtualProtect = (PFNVirtualProtect)apis.pfnGetProcAddress(hKernel32, "VirtualProtect");
	apis.pfnGetModuleHandleA = (PFNLGetModuleHandleA)apis.pfnGetProcAddress(hKernel32, "GetModuleHandleA");

	apis.pfnRemoveVectoredExceptionHandler = (PFNRemoveVectoredExceptionHandler)apis.pfnGetProcAddress(hKernel32, "RemoveVectoredExceptionHandler");
	apis.pfnAddVectoredExceptionHandler = (PFNAddVectoredExceptionHandler)apis.pfnGetProcAddress(hKernel32, "AddVectoredExceptionHandler");
	apis.pfnExitProcess = (PFNExitProcess)MyGetProcAddress(hKernel32, "ExitProcess");
	apis.pfnVirtualAlloc = (PFNVirtualAlloc)MyGetProcAddress(hKernel32, "VirtualAlloc");
	apis.pfnGlobalAlloc = (PFNGlobalAlloc)MyGetProcAddress(hKernel32, "GlobalAlloc");
	apis.pfnIsDebuggerPresent = (PFNIsDebuggerPresent)apis.pfnGetProcAddress(hKernel32, "IsDebuggerPresent");

	//��aplib.dll�л�ȡ����
	HMODULE hmaplib = apis.pfnLoadLibraryA("aplib.dll");
	apis.pfnaPsafe_get_orig_size = (PFNaPsafe_get_orig_size)apis.pfnGetProcAddress(hmaplib, "_aPsafe_get_orig_size");
	apis.pfnaPsafe_depack = (PFNaPsafe_depack)apis.pfnGetProcAddress(hmaplib, "_aPsafe_depack");


	//��user32�л�ȡ����
	HMODULE hUser32 = apis.pfnLoadLibraryA("user32.dll");
	apis.pfnMessageBox = (PFNMessageBox)MyGetProcAddress(hUser32, "MessageBoxW");
	apis.pfnGetDlgItem = (PFNGetDlgItem)MyGetProcAddress(hUser32, "GetDlgItem");
	apis.pfnGetWindowText = (PFNGetWindowText)MyGetProcAddress(hUser32, "GetWindowTextW");
	apis.pfnDestroyWindow = (PFNDestroyWindow)MyGetProcAddress(hUser32, "DestroyWindow");
	apis.pfnGetClientRect = (PFNGetClientRect)MyGetProcAddress(hUser32, "GetClientRect");
	apis.pfnPostQuitMessage = (PFNPostQuitMessage)MyGetProcAddress(hUser32, "PostQuitMessage");
	apis.pfnDefWindowProc = (PFNDefWindowProc)MyGetProcAddress(hUser32, "DefWindowProcW");
	apis.pfnLoadIcon = (PFNLoadIcon)MyGetProcAddress(hUser32, "LoadIconW");
	apis.pfnLoadCursor = (PFNLoadCursor)MyGetProcAddress(hUser32, "LoadCursorW");
	apis.pfnRegisterClass = (PFNRegisterClass)MyGetProcAddress(hUser32, "RegisterClassW");
	apis.pfnCreateWindow = (PFNPFNCreateWindow)MyGetProcAddress(hUser32, "CreateWindowExW");
	apis.pfnShowWindow = (PFNShowWindow)MyGetProcAddress(hUser32, "ShowWindow");
	apis.pfnGetMessage = (PFNGetMessage)MyGetProcAddress(hUser32, "GetMessageW");
	apis.pfnTranslateMessage = (PFNTranslateMessage)MyGetProcAddress(hUser32, "TranslateMessage");
	apis.pfnDispatchMessage = (PFNDispatchMessage)MyGetProcAddress(hUser32, "DispatchMessageW");

}
//SDK ���ڻص�
LRESULT CALLBACK WindowProc(_In_ HWND hWnd, /*���ھ�� */ _In_ UINT uMsg, /*��ϢID */ _In_ WPARAM wParam, /*��Ϣ����1 */ _In_ LPARAM lParam /*��Ϣ����2 */)
{
	// 	PAINTSTRUCT ps;
	// 	HDC hdc = {};
	// 	RECT re;
	DWORD wHigh = HIWORD(wParam);
	DWORD wLow = LOWORD(wParam);
	switch (uMsg)
	{
	case WM_COMMAND:
		switch (wLow){
		case 0x1001:
		{
			HWND hEdit = apis.pfnGetDlgItem(hWnd, 0x1002);
			TCHAR buf[20] = {};
			TCHAR str[] = L"15pb";
			apis.pfnGetWindowText(hEdit, buf, 20);
			if (CmpStr(buf, str) == 0)
			{
				apis.pfnMessageBox(hWnd, TEXT("������ȷ��"), TEXT("��֤��"), MB_OK);
				apis.pfnDestroyWindow(hWnd);
				break;
			}
			else
			{
				apis.pfnMessageBox(hWnd, TEXT("�������"), TEXT("��֤��"), MB_OK);
				apis.pfnExitProcess(0);
			}
		}
		}
	case WM_PAINT:
		break;
	case WM_CLOSE:
		apis.pfnDestroyWindow(hWnd);	//���ٴ��ڣ�����WM_DESTROY��Ϣ
		break;
	case WM_DESTROY:
		apis.pfnPostQuitMessage(0);		//WM_QUIT
		break;
	default:
		break;
	}
	//��ϵͳ��Ĭ�ϴ���������
	return apis.pfnDefWindowProc(hWnd, uMsg, wParam, lParam);
}
//SDK ����
int sdkWindow()
{
	HINSTANCE hInstance = apis.pfnGetModuleHandleA(NULL);
	//1,���һ��������
	WNDCLASS wce = { 0 };
	wce.style = CS_HREDRAW | CS_VREDRAW;	//���ˮƽ�ػ�|��ֱ�ػ�
	wce.lpfnWndProc = WindowProc; //����Ļص�����
	wce.cbClsExtra = 0;
	wce.cbWndExtra = 0;
	wce.hInstance = hInstance;		//ʵ�����
	wce.hIcon = apis.pfnLoadIcon(hInstance, IDI_APPLICATION);	//ͼ����Դ
	wce.hCursor = apis.pfnLoadCursor(nullptr, IDC_ARROW);	//�����Դ
	wce.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);	//
	wce.lpszMenuName = NULL;	//
	wce.lpszClassName = TEXT("TangPack");	//��Ҫ���裬��������
										//2,ע�ᴰ����
	apis.pfnRegisterClass(&wce);
	//3,��������

	HWND hWnd = apis.pfnCreateWindow(
		0,
		TEXT("TangPack"),				//��������
		TEXT("PassWord Validate"),			//���ڱ��⣬title
		WS_ACTIVECAPTION | WS_VISIBLE,	//���ڷ��WS_ACTIVECAPTION��ȥ�������С���رհ�ť
		400, 100,	//������ʼλ��
		500, 200,	//���ڿ��
		NULL,		//������
		NULL,		//�˵����
		hInstance,	//ʵ�����
		NULL		//������Ϣ
	);
	HWND hBtn = apis.pfnCreateWindow(
		0,
		TEXT("button"),				//��������
		TEXT("ȷ��"),			//���ڱ��⣬title
		BS_PUSHBUTTON | WS_CHILD | WS_VISIBLE,		//���ڷ��
		150, 120,	//������ʼλ��
		100, 30,	//���ڿ��
		hWnd,		//������
		(HMENU)0x1001,		//�Ӵ���ID
		hInstance,	//ʵ�����
		NULL		//������Ϣ
	);
	HWND hEdit1 = apis.pfnCreateWindow(
		0,
		TEXT("edit"),				//��������
		TEXT(""),			//���ڱ��⣬title
		WS_BORDER | WS_CHILD | WS_VISIBLE,		//���ڷ��
		150, 80,	//������ʼλ��
		150, 30,	//���ڿ��
		hWnd,		//������
		(HMENU)0x1002,		//�Ӵ���ID
		hInstance,	//ʵ�����
		NULL		//������Ϣ
	);
	HWND hStaticText = apis.pfnCreateWindow(
		0,
		TEXT("static"),				//��������
		TEXT("����������"),			//���ڱ��⣬title
		SS_LEFT | WS_CHILD | WS_VISIBLE,		//���ڷ��
		150, 50,	//������ʼλ��
		150, 30,	//���ڿ��
		hWnd,		//������
		(HMENU)0x1003,		//�Ӵ���ID
		hInstance,	//ʵ�����
		NULL		//������Ϣ
	);
	//��ʾˢ�´���
	apis.pfnShowWindow(hWnd, SW_SHOW);
	//	UpdateWindow(hWnd);
	//��Ϣѭ��
	MSG msg = {};
	//������Ϣ���ַ�����ͬ�Ĵ���
	while (apis.pfnGetMessage(&msg,//���յ�����Ϣ������
		NULL,	//NULL��ʾ��ǰ�߳������Ĵ��ڵ�������Ϣ��������
		0,		//���յ�����С��Ϣֵ
		0))		//���յ��������Ϣֵ
	{
		apis.pfnTranslateMessage(&msg);
		//��ͬ���ڵ���Ϣ�ַ�����Ӧ�Ļص�����
		apis.pfnDispatchMessage(&msg);
	}
	return msg.wParam;
}


//��ѹ��
void decompress()
{

	/*HMODULE hModule = GetModuleHandle(NULL);
	IMAGE_DOS_HEADER* lpDosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* lpNtHeader = (IMAGE_NT_HEADERS*)(lpDosHeader->e_lfanew + (DWORD)hModule);
	IMAGE_SECTION_HEADER* lpSecHeader = (IMAGE_SECTION_HEADER*)((DWORD)hModule +
		lpDosHeader->e_lfanew + sizeof(lpNtHeader->Signature) +
		sizeof(lpNtHeader->FileHeader) +
		lpNtHeader->FileHeader.SizeOfOptionalHeader);
	DWORD dwPackedSize = lpSecHeader->Misc.VirtualSize;*/

	//==================

	char* pSrc = (char*)(g_stubConf.dwTextSectionRva + (DWORD)apis.pfnGetModuleHandleA(NULL));
	//�޸��ڴ�����
	DWORD oldProtect;
	apis.pfnVirtualProtect(pSrc, g_stubConf.dwTextSectionSize, PAGE_READWRITE, &oldProtect);

	char* Dst = (PCHAR)(apis.pfnGlobalAlloc(0x40, g_stubConf.dwTextSectionSize));
	for (int i = 0; i < g_stubConf.dwTextSectionSize; i++)
	{
		Dst[i] = pSrc[i];
	}
	DWORD OriLen = apis.pfnaPsafe_get_orig_size(Dst);

	DWORD dwPackLen = apis.pfnaPsafe_depack(Dst, g_stubConf.dwTextSectionSize, pSrc, OriLen);
	//�޸Ļ�ԭ�����ڴ�����
	apis.pfnVirtualProtect(pSrc, g_stubConf.dwTextSectionSize, oldProtect, &oldProtect);


	//==================

	//DWORD* lpDwAddress = (DWORD*)((DWORD)hModule + lpSecHeader->VirtualAddress);
	////���ȴ���tls
	////tls
	//DWORD dwSizeOfRawData = *lpDwAddress;
	//IMAGE_TLS_DIRECTORY* lpTlsDir = NULL;
	//if (dwSizeOfRawData == 0)
	//{
	//	lpDwAddress++;
	//	lpDwAddress++;
	//	lpDwAddress++;
	//	lpDwAddress++;
	//}
	//else
	//{
	//	lpDwAddress++;
	//	DWORD dwDestRVA = *lpDwAddress;
	//	lpDwAddress++;
	//	DWORD dwSrcRVA = *lpDwAddress;
	//	memcpy(((char*)hModule + dwDestRVA), (LPVOID)((DWORD)hModule + dwSrcRVA), dwSizeOfRawData);
	//	lpDwAddress++;
	//	g_lpTlsDir = (IMAGE_TLS_DIRECTORY*)((DWORD)hModule + *lpDwAddress);
	//	lpDwAddress++;
	//}

}



BOOL isDebug()
{
	bool bDebug = false;
	//���´�����PEB��BeingDebugged��ֵ

	_asm
	{
		mov ebx, fs:[0x30]
		xor eax, eax
		mov al, [ebx + 2]
		mov[bDebug], al
	}


	if (bDebug)
	{
		apis.pfnMessageBox(0, 0, L"���ڱ�����", 0);
	}
}




//�ǵ���ں���
STUB_API void __declspec(naked) start()
{
	//��ָ��
	JUNK_CODE_02;
	JUNK_CODE_01;
	// ��ȡAPI
	GetAPIs();

	CheckDebugger();
	if (isVehHardware()){
		apis.pfnMessageBox(0, 0, L"���ڱ�����", 0);
	}

	isDebug();

	//sdk����
	sdkWindow();
	//apis.pfnMessageBox(0, 0, 0, 0);

	//�Ƚ�ѹ����Ȼ�����
	decompress();

	// ��������
	decrypt();

	//�޸��ض�λ
	//FixReloc();


	//CallTls();


	// ��ת�����ӿǳ������ڵ�.
	//��ָ��
	JUNK_CODE_04;

	JUNK_CODE_03;
}


BOOL VehHardwarei = FALSE;
DWORD Vehaddr;


BOOL isVehHardware()
{
	PVOID VEHandle = apis.pfnAddVectoredExceptionHandler(1, VehHardwareExceptionFilter);

	if (VEHandle != NULL)
	{
		apis.pfnRemoveVectoredExceptionHandler(VEHandle);
	}
	return VehHardwarei;
}

void CheckDebugger()
{
	if (apis.pfnIsDebuggerPresent() == true)
	{
		apis.pfnExitProcess(0);
	}
}



LONG NTAPI VehHardwareExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
	if (ExceptionInfo->ContextRecord->Dr0 != 0
		|| ExceptionInfo->ContextRecord->Dr1 != 0
		|| ExceptionInfo->ContextRecord->Dr2 != 0
		|| ExceptionInfo->ContextRecord->Dr3 != 0)
	{
		VehHardwarei = TRUE;
		ExceptionInfo->ContextRecord->Dr0 = 0;
		ExceptionInfo->ContextRecord->Dr1 = 0;
		ExceptionInfo->ContextRecord->Dr2 = 0;
		ExceptionInfo->ContextRecord->Dr3 = 0;

	}
	ExceptionInfo->ContextRecord->Eip = Vehaddr;
	return EXCEPTION_CONTINUE_EXECUTION;
}









// stub.cpp : 定义 DLL 应用程序的导出函数。
//
#include "stdafx.h"
#include "stub.h"

#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text") 
#pragma comment(linker, "/section:.text,RWE")


//
// 一个被导出的结构体变量
// 里面保存着被加壳程序的信息,如文件头,扩展头,
// 区段表等.
// 由于这个结构体已经被导出, 因此,可以直接通过
// 解析导出表来得到它.
STUB_API StubConf g_stubConf = { 0xAAAAAAAA };


//API函数指针原型
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


/// 保存API的全局变量
APIS apis;


void FixReloc()
{
	//以下是重定位
	DWORD *tmp;
	DWORD g_dwImageBase = (DWORD)apis.pfnGetModuleHandleA(NULL);
	if (g_stubConf.RelocRva)  //如果没有重定位表表示不用重定位，跳过重定位代码
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

//自定义比较字符串函数 窄字符则将wchar_t换成unsigned char
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
		// 以序号方式导入
		WORD ord = (SIZE_T)pszName & 0xFFFF;
		DWORD* pEat = (DWORD*)(pExpDir->AddressOfFunctions + (SIZE_T)hModule);
		return (LPVOID)(pEat[ord - pExpDir->Base] + (SIZE_T)hModule);
	}


	// 遍历名称表, 找到名称
	PDWORD pEnt = (PDWORD)(pExpDir->AddressOfNames + (SIZE_T)hModule);
	char* pName = NULL;
	for (DWORD i = 0; i < pExpDir->NumberOfNames; ++i) {
		pName = (char*)(pEnt[i] + (SIZE_T)hModule);
		if (strcmp(pszName, pName) == 0) {
			// 找到了函数
			WORD* pEot = (WORD*)(pExpDir->AddressOfNameOrdinals + (SIZE_T)hModule);
			// 从序号表中取出地址表的下标
			DWORD index = pEot[i];
			DWORD* pEat = (DWORD*)(pExpDir->AddressOfFunctions + (SIZE_T)hModule);
			SIZE_T address = pEat[index] + (SIZE_T)hModule;
			return (LPVOID)address;
		}
	}
	return NULL;
}


void GetAPIs() {
	// 1. 找到kernel32的加载基址
	// 找到GetProcAddress和LoadLibrary函数的地址
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
	// 获取要用到的函数地址
	// 从kernel32中获取函数
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

	//从aplib.dll中获取函数
	HMODULE hmaplib = apis.pfnLoadLibraryA("aplib.dll");
	apis.pfnaPsafe_get_orig_size = (PFNaPsafe_get_orig_size)apis.pfnGetProcAddress(hmaplib, "_aPsafe_get_orig_size");
	apis.pfnaPsafe_depack = (PFNaPsafe_depack)apis.pfnGetProcAddress(hmaplib, "_aPsafe_depack");


	//从user32中获取函数
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
//SDK 窗口回调
LRESULT CALLBACK WindowProc(_In_ HWND hWnd, /*窗口句柄 */ _In_ UINT uMsg, /*消息ID */ _In_ WPARAM wParam, /*消息参数1 */ _In_ LPARAM lParam /*消息参数2 */)
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
				apis.pfnMessageBox(hWnd, TEXT("密码正确！"), TEXT("验证！"), MB_OK);
				apis.pfnDestroyWindow(hWnd);
				break;
			}
			else
			{
				apis.pfnMessageBox(hWnd, TEXT("密码错误！"), TEXT("验证！"), MB_OK);
				apis.pfnExitProcess(0);
			}
		}
		}
	case WM_PAINT:
		break;
	case WM_CLOSE:
		apis.pfnDestroyWindow(hWnd);	//销毁窗口，发送WM_DESTROY消息
		break;
	case WM_DESTROY:
		apis.pfnPostQuitMessage(0);		//WM_QUIT
		break;
	default:
		break;
	}
	//用系统的默认处理函数处理
	return apis.pfnDefWindowProc(hWnd, uMsg, wParam, lParam);
}
//SDK 弹窗
int sdkWindow()
{
	HINSTANCE hInstance = apis.pfnGetModuleHandleA(NULL);
	//1,设计一个窗口类
	WNDCLASS wce = { 0 };
	wce.style = CS_HREDRAW | CS_VREDRAW;	//风格水平重绘|垂直重绘
	wce.lpfnWndProc = WindowProc; //上面的回调函数
	wce.cbClsExtra = 0;
	wce.cbWndExtra = 0;
	wce.hInstance = hInstance;		//实例句柄
	wce.hIcon = apis.pfnLoadIcon(hInstance, IDI_APPLICATION);	//图标资源
	wce.hCursor = apis.pfnLoadCursor(nullptr, IDC_ARROW);	//鼠标资源
	wce.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);	//
	wce.lpszMenuName = NULL;	//
	wce.lpszClassName = TEXT("TangPack");	//重要必需，窗口类名
										//2,注册窗口类
	apis.pfnRegisterClass(&wce);
	//3,创建窗口

	HWND hWnd = apis.pfnCreateWindow(
		0,
		TEXT("TangPack"),				//窗口类名
		TEXT("PassWord Validate"),			//窗口标题，title
		WS_ACTIVECAPTION | WS_VISIBLE,	//窗口风格WS_ACTIVECAPTION可去除最大化最小化关闭按钮
		400, 100,	//窗口起始位置
		500, 200,	//窗口宽高
		NULL,		//父窗口
		NULL,		//菜单句柄
		hInstance,	//实例句柄
		NULL		//附加信息
	);
	HWND hBtn = apis.pfnCreateWindow(
		0,
		TEXT("button"),				//窗口类名
		TEXT("确定"),			//窗口标题，title
		BS_PUSHBUTTON | WS_CHILD | WS_VISIBLE,		//窗口风格
		150, 120,	//窗口起始位置
		100, 30,	//窗口宽高
		hWnd,		//父窗口
		(HMENU)0x1001,		//子窗口ID
		hInstance,	//实例句柄
		NULL		//附加信息
	);
	HWND hEdit1 = apis.pfnCreateWindow(
		0,
		TEXT("edit"),				//窗口类名
		TEXT(""),			//窗口标题，title
		WS_BORDER | WS_CHILD | WS_VISIBLE,		//窗口风格
		150, 80,	//窗口起始位置
		150, 30,	//窗口宽高
		hWnd,		//父窗口
		(HMENU)0x1002,		//子窗口ID
		hInstance,	//实例句柄
		NULL		//附加信息
	);
	HWND hStaticText = apis.pfnCreateWindow(
		0,
		TEXT("static"),				//窗口类名
		TEXT("请输入密码"),			//窗口标题，title
		SS_LEFT | WS_CHILD | WS_VISIBLE,		//窗口风格
		150, 50,	//窗口起始位置
		150, 30,	//窗口宽高
		hWnd,		//父窗口
		(HMENU)0x1003,		//子窗口ID
		hInstance,	//实例句柄
		NULL		//附加信息
	);
	//显示刷新窗口
	apis.pfnShowWindow(hWnd, SW_SHOW);
	//	UpdateWindow(hWnd);
	//消息循环
	MSG msg = {};
	//接收消息，分发给不同的窗口
	while (apis.pfnGetMessage(&msg,//接收到的消息放在哪
		NULL,	//NULL表示当前线程所属的窗口的所有消息都交给我
		0,		//接收到的最小消息值
		0))		//接收到的最大消息值
	{
		apis.pfnTranslateMessage(&msg);
		//不同窗口的消息分发给对应的回调函数
		apis.pfnDispatchMessage(&msg);
	}
	return msg.wParam;
}


//解压缩
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
	//修改内存属性
	DWORD oldProtect;
	apis.pfnVirtualProtect(pSrc, g_stubConf.dwTextSectionSize, PAGE_READWRITE, &oldProtect);

	char* Dst = (PCHAR)(apis.pfnGlobalAlloc(0x40, g_stubConf.dwTextSectionSize));
	for (int i = 0; i < g_stubConf.dwTextSectionSize; i++)
	{
		Dst[i] = pSrc[i];
	}
	DWORD OriLen = apis.pfnaPsafe_get_orig_size(Dst);

	DWORD dwPackLen = apis.pfnaPsafe_depack(Dst, g_stubConf.dwTextSectionSize, pSrc, OriLen);
	//修改回原来的内存属性
	apis.pfnVirtualProtect(pSrc, g_stubConf.dwTextSectionSize, oldProtect, &oldProtect);


	//==================

	//DWORD* lpDwAddress = (DWORD*)((DWORD)hModule + lpSecHeader->VirtualAddress);
	////首先处理tls
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
	//以下代码检查PEB的BeingDebugged的值

	_asm
	{
		mov ebx, fs:[0x30]
		xor eax, eax
		mov al, [ebx + 2]
		mov[bDebug], al
	}


	if (bDebug)
	{
		apis.pfnMessageBox(0, 0, L"正在被调试", 0);
	}
}




//壳的入口函数
STUB_API void __declspec(naked) start()
{
	//花指令
	JUNK_CODE_02;
	JUNK_CODE_01;
	// 获取API
	GetAPIs();

	CheckDebugger();
	if (isVehHardware()){
		apis.pfnMessageBox(0, 0, L"正在被调试", 0);
	}

	isDebug();

	//sdk弹窗
	sdkWindow();
	//apis.pfnMessageBox(0, 0, 0, 0);

	//先解压缩，然后解密
	decompress();

	// 解密数据
	decrypt();

	//修复重定位
	//FixReloc();


	//CallTls();


	// 跳转到被加壳程序的入口点.
	//花指令
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









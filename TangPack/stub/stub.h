#pragma once
#include<windows.h>
// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 STUB_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// STUB_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef STUB_EXPORTS
#define STUB_API __declspec(dllexport)
#else
#define STUB_API __declspec(dllimport)
#endif
#ifdef __cplusplus
extern"C" {
#endif // __cplusplus

#define JUNK_CODE_01 __asm \
	/*花指令宏1*/     \
{                          \
	__asm pushad           \
    __asm popad            \
}
#define JUNK_CODE_02 __asm \
	/*花指令宏2*/	   \
{						   \
	__asm push eax			   \
	__asm 	jmp sig1		   \
	__asm 	_emit 0xEB		   \
	__asm sig1:				   \
	__asm mov eax, 0x1		   \
	__asm 	jmp sig2		   \
	__asm 	_emit 0xE9		   \
	__asm sig2 :				   \
	__asm 	 add eax, 1		   \
	__asm 	 jmp sig3		   \
	__asm 	 _emit 0xE9		   \
	__asm 	 _emit 0x20		   \
	__asm  sig3 :				   \
	__asm 	  sub eax, 1	   \
	__asm 	  pop eax		   \
}


#define JUNK_CODE_03 __asm  \
/*花指令宏3*/  \
{   \
	__asm call l1   \
	__asm l1:   \
	__asm pop eax  \
	__asm mov ebx, eax  \
	__asm call f1  \
	__asm _EMIT 0xEA  \
	__asm jmp l2  \
	__asm f1 :  \
	__asm pop ebx  \
	__asm inc ebx  \
	__asm push ebx  \
	__asm mov eax, 0x11111111  \
	__asm ret  \
	__asm l2:  \
	__asm call f2  \
	__asm mov ebx, 0x33333333  \
	__asm jmp e  \
	__asm f2:  \
	__asm mov ebx, 0x11111111   \
	__asm pop ebx  \
	__asm mov ebx, offset e  \
	__asm push ebx   \
	__asm ret   \
	__asm e:   \
	__asm mov ebx, 0x22222222  \
}


#define JUNK_CODE_04 __asm  \
{\
__asm push -1   \
__asm push 0    \
__asm push 0    \
__asm mov EAX, DWORD PTR FS : [0]  \
__asm push EAX  \
__asm mov DWORD PTR FS : [0], ESP  \
__asm sub ESP, 1   \
__asm push EBX   \
__asm push ESI   \
__asm push EDI   \
__asm pop EAX   \
__asm pop EAX     \
__asm nop     \
__asm pop EAX   \
__asm nop   \
__asm add ESP, 1   \
__asm pop EAX   \
__asm mov DWORD PTR FS : [0], EAX   \
__asm pop EAX   \
__asm pop EAX   \
__asm nop   \
__asm pop EAX   \
__asm nop   \
__asm pop EAX   \
__asm mov EBP, EAX   \
__asm mov eax,g_stubConf.ntheader.OptionalHeader.AddressOfEntryPoint   \
__asm add eax,g_stubConf.ntheader.OptionalHeader.ImageBase   \
__asm jmp eax   \
__asm ret   \
}


//壳代码结构体
typedef struct StubConf {
	DWORD dwTextSectionRva;
	DWORD dwTextSectionSize;
	unsigned char key;

	IMAGE_NT_HEADERS		ntheader; // 用来记录被加壳程序的原始头部
	IMAGE_SECTION_HEADER	scnHeader[13]; //用来记录被加壳程序的区段头


	void* StartAddreass;		//起始函数地址
	void* TargetOep;			//目标程序OEP
	unsigned long CompressSize;			//压缩后的长度
	unsigned long UnCompressSize;		//压缩前的长度
	PBYTE bCompress;			//存放压缩后的字节的缓冲区地址
	DWORD dwOldINTRva;			//旧的INT的RVA
	DWORD dwOldRelocRva;		//旧的重定位表的RVA
	DWORD dwOldRelocSize;		//旧的重定位表的size



	DWORD dllOep;               //这里存放着解壳代码的起始执行位置
	DWORD TargetOepRva;            //加壳后目标程序的原始OEP
	DWORD dwReloc;              //重定位后的地址
	DWORD dwSize;               //大小
	LPCTSTR temp;               //字符串
								//////////////////////////////////////////////////////////////
	DWORD TlsIndex;		        // tls序号
	DWORD TlsCallbackFuncRva;   // tls回调函数指针数组
	DWORD ImageBase;
	DWORD ImportTableRva;		//iat的rva
	DWORD RelocRva;		        //重定位表rva
	DWORD PackSectionNumber;    // 压缩区段数量
	DWORD packSectionRva;       // 压缩区段的rva
	DWORD packSectionSize;      //压缩区段的大小
	DWORD PackInfomation[50][2];// 压缩区段中每个区段的index和大小


	BOOL bIsTlsUseful; 

}StubConf,*PStubConf;

extern STUB_API StubConf g_stubConf;

STUB_API void  start(); // 壳的入口函数.

//重定位结构体
typedef struct _RELOCTYPE {
	unsigned short offset : 12;//偏移值
	unsigned short type : 4;//重定位属性    3需要修改的
}RELOCTYPE, *PRELOCTYPE;


#ifdef __cplusplus
}
#endif // __cplusplus



//API函数指针原型
typedef HMODULE(WINAPI *PFNLGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
typedef LPVOID(WINAPI *PFNVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef void(WINAPI *PFNExitProcess)(_In_ UINT uExitCode);
typedef int (WINAPI *PFNMessageBox)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);


//字符串比较函数
int CmpStr(const wchar_t * src, const wchar_t * dst);

//创建窗口回调函数
LRESULT CALLBACK WindowProc(_In_ HWND hWnd,		//窗口句柄
	_In_ UINT uMsg,		//消息ID
	_In_ WPARAM wParam,	//消息参数1
	_In_ LPARAM lParam	//消息参数2
);

//sdk弹窗
//int sdkWindow(_In_ HINSTANCE hInstance);
int sdkWindow();

//API函数指针原型
typedef HWND(WINAPI *PFNGetDlgItem)(_In_opt_ HWND hDlg, _In_ int nIDDlgItem);
typedef DWORD(WINAPI *PFNGetWindowText)(_In_   HWND hWnd, _Out_  LPTSTR lpString, _In_   int nMaxCount);
typedef BOOL(WINAPI *PFNDestroyWindow)(_In_ HWND hWnd);
typedef BOOL(WINAPI *PFNGetClientRect)(_In_ HWND hWnd, _Out_ LPRECT lpRect);
typedef VOID(WINAPI *PFNPostQuitMessage)(_In_ int nExitCode);
typedef LRESULT(WINAPI *PFNDefWindowProc)(_In_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam);
typedef HICON(WINAPI *PFNLoadIcon)(_In_opt_ HINSTANCE hInstance, _In_ LPCWSTR lpIconName);
typedef HCURSOR(WINAPI *PFNLoadCursor)(_In_opt_  HINSTANCE hInstance, _In_      LPCTSTR lpCursorName);
typedef ATOM(WINAPI *PFNRegisterClass)(_In_ CONST WNDCLASSW *lpWndClass);
typedef HWND(WINAPI *PFNPFNCreateWindow)(_In_ DWORD dwExStyle, _In_opt_  LPCTSTR lpClassName, _In_opt_  LPCTSTR lpWindowName, _In_ DWORD dwStyle, _In_ int x, _In_ int y, _In_  int nWidth,
	_In_ int nHeight, _In_opt_  HWND hWndParent, _In_opt_  HMENU hMenu, _In_opt_  HINSTANCE hInstance, _In_opt_  LPVOID lpParam);
typedef BOOL(WINAPI *PFNShowWindow)(_In_ HWND hWnd, _In_ int nCmdShow);
typedef BOOL(WINAPI *PFNGetMessage)(_Out_ LPMSG lpMsg, _In_opt_ HWND hWnd, _In_ UINT wMsgFilterMin, _In_ UINT wMsgFilterMax);
typedef BOOL(WINAPI *PFNTranslateMessage)(_In_ CONST MSG *lpMsg);
typedef LRESULT(WINAPI *PFNDispatchMessage)(_In_ CONST MSG *lpMsg);


//解压缩
void  decompress();
//解压用到的函数
typedef HGLOBAL(WINAPI* PFNGlobalAlloc)(UINT, SIZE_T);
typedef DWORD(WINAPI*PFNaPsafe_depack)(char*, DWORD, char*, DWORD);
typedef DWORD(WINAPI*PFNaPsafe_get_orig_size)(const char*);

//反调试
typedef PVOID(WINAPI* PFNAddVectoredExceptionHandler)(_In_ ULONG First, _In_ PVECTORED_EXCEPTION_HANDLER Handler);
typedef ULONG(WINAPI *PFNRemoveVectoredExceptionHandler)(_In_ PVOID Handler);
LONG NTAPI VehHardwareExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo);
BOOL isVehHardware();
void CheckDebugger();
typedef BOOL(WINAPI* PFNIsDebuggerPresent)(void);

//是否在被调试
BOOL isDebug();

IMAGE_TLS_DIRECTORY* g_lpTlsDir = NULL;

//解压完检查是否存在TLS函数
//void CallTls();

DWORD g_dwOldImp = 0;
//修复IAT
//void RecoverIAT();

//修复IAT2
//void FixIAT();

//修复重定位1
//void FixSrcReloc();

//修复重定位2
void FixReloc();


//void GetTLSRva();

//void GetDllBaseRelocRva();




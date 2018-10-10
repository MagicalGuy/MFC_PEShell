#pragma once
#include<windows.h>
// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� STUB_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// STUB_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifdef STUB_EXPORTS
#define STUB_API __declspec(dllexport)
#else
#define STUB_API __declspec(dllimport)
#endif
#ifdef __cplusplus
extern"C" {
#endif // __cplusplus

#define JUNK_CODE_01 __asm \
	/*��ָ���1*/     \
{                          \
	__asm pushad           \
    __asm popad            \
}
#define JUNK_CODE_02 __asm \
	/*��ָ���2*/	   \
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
/*��ָ���3*/  \
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


//�Ǵ���ṹ��
typedef struct StubConf {
	DWORD dwTextSectionRva;
	DWORD dwTextSectionSize;
	unsigned char key;

	IMAGE_NT_HEADERS		ntheader; // ������¼���ӿǳ����ԭʼͷ��
	IMAGE_SECTION_HEADER	scnHeader[13]; //������¼���ӿǳ��������ͷ


	void* StartAddreass;		//��ʼ������ַ
	void* TargetOep;			//Ŀ�����OEP
	unsigned long CompressSize;			//ѹ����ĳ���
	unsigned long UnCompressSize;		//ѹ��ǰ�ĳ���
	PBYTE bCompress;			//���ѹ������ֽڵĻ�������ַ
	DWORD dwOldINTRva;			//�ɵ�INT��RVA
	DWORD dwOldRelocRva;		//�ɵ��ض�λ���RVA
	DWORD dwOldRelocSize;		//�ɵ��ض�λ���size



	DWORD dllOep;               //�������Ž�Ǵ������ʼִ��λ��
	DWORD TargetOepRva;            //�ӿǺ�Ŀ������ԭʼOEP
	DWORD dwReloc;              //�ض�λ��ĵ�ַ
	DWORD dwSize;               //��С
	LPCTSTR temp;               //�ַ���
								//////////////////////////////////////////////////////////////
	DWORD TlsIndex;		        // tls���
	DWORD TlsCallbackFuncRva;   // tls�ص�����ָ������
	DWORD ImageBase;
	DWORD ImportTableRva;		//iat��rva
	DWORD RelocRva;		        //�ض�λ��rva
	DWORD PackSectionNumber;    // ѹ����������
	DWORD packSectionRva;       // ѹ�����ε�rva
	DWORD packSectionSize;      //ѹ�����εĴ�С
	DWORD PackInfomation[50][2];// ѹ��������ÿ�����ε�index�ʹ�С


	BOOL bIsTlsUseful; 

}StubConf,*PStubConf;

extern STUB_API StubConf g_stubConf;

STUB_API void  start(); // �ǵ���ں���.

//�ض�λ�ṹ��
typedef struct _RELOCTYPE {
	unsigned short offset : 12;//ƫ��ֵ
	unsigned short type : 4;//�ض�λ����    3��Ҫ�޸ĵ�
}RELOCTYPE, *PRELOCTYPE;


#ifdef __cplusplus
}
#endif // __cplusplus



//API����ָ��ԭ��
typedef HMODULE(WINAPI *PFNLGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
typedef LPVOID(WINAPI *PFNVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef void(WINAPI *PFNExitProcess)(_In_ UINT uExitCode);
typedef int (WINAPI *PFNMessageBox)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);


//�ַ����ȽϺ���
int CmpStr(const wchar_t * src, const wchar_t * dst);

//�������ڻص�����
LRESULT CALLBACK WindowProc(_In_ HWND hWnd,		//���ھ��
	_In_ UINT uMsg,		//��ϢID
	_In_ WPARAM wParam,	//��Ϣ����1
	_In_ LPARAM lParam	//��Ϣ����2
);

//sdk����
//int sdkWindow(_In_ HINSTANCE hInstance);
int sdkWindow();

//API����ָ��ԭ��
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


//��ѹ��
void  decompress();
//��ѹ�õ��ĺ���
typedef HGLOBAL(WINAPI* PFNGlobalAlloc)(UINT, SIZE_T);
typedef DWORD(WINAPI*PFNaPsafe_depack)(char*, DWORD, char*, DWORD);
typedef DWORD(WINAPI*PFNaPsafe_get_orig_size)(const char*);

//������
typedef PVOID(WINAPI* PFNAddVectoredExceptionHandler)(_In_ ULONG First, _In_ PVECTORED_EXCEPTION_HANDLER Handler);
typedef ULONG(WINAPI *PFNRemoveVectoredExceptionHandler)(_In_ PVOID Handler);
LONG NTAPI VehHardwareExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo);
BOOL isVehHardware();
void CheckDebugger();
typedef BOOL(WINAPI* PFNIsDebuggerPresent)(void);

//�Ƿ��ڱ�����
BOOL isDebug();

IMAGE_TLS_DIRECTORY* g_lpTlsDir = NULL;

//��ѹ�����Ƿ����TLS����
//void CallTls();

DWORD g_dwOldImp = 0;
//�޸�IAT
//void RecoverIAT();

//�޸�IAT2
//void FixIAT();

//�޸��ض�λ1
//void FixSrcReloc();

//�޸��ض�λ2
void FixReloc();


//void GetTLSRva();

//void GetDllBaseRelocRva();




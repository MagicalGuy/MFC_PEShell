#pragma once
#include <windows.h>
//#include "../stub/stub.h"

class PeFileHandling {
public:
	PeFileHandling();
	~PeFileHandling();

	//压缩代码
	void compress();

	//打开文件
	bool open(CString pszPath);

	//关闭文件，释放空间
	void close();

	// 添加一个新区段, 并把新区段的头部返回.
	// 如果添加失败,就返回NULL
	//参数：区段名  区段数据  区段大小
	IMAGE_SECTION_HEADER* addSection(char name[8],void* pSectionData,DWORD dwSectionSize);

	// 将一段二进制数据拷贝指定的区段中
	void setSectioData(IMAGE_SECTION_HEADER* pScn,void* pSectionData,DWORD dwSectionSize);

	// 根据传入的区段名,返回区段头,如果不存在,返回NULL
	IMAGE_SECTION_HEADER* getSection(const char* name);

	//对齐大小
	DWORD calcAligmentSize(DWORD srcSize, DWORD aligment);

	//rva转foa
	DWORD RvaToOffset(DWORD rva);

	// 返回符号的RVA
	DWORD getProcAddress(const char* pszName);

	// 修复stub部分的重定位数据
	// 地址 = 加载基址 + 段首RVA + 段内偏移
	// stub是一个dll,它的代码要从dll中移植到exe中,默认加载基址发生了改变
	// 然后stub将被当成一个新区段被移植到exe中的新区段中,段首RVA也发生了
	// 改变, 因此 , 需要将那些使用了VA地址的代码修正.
	// 
	void fixStubRva(DWORD oldImageBase, DWORD newImageBase,
		DWORD oldSectionRva, DWORD newSectionRva);



	//修复INT
	//void FixINT(PCHAR pBuf);


	//增加重定位
	//对于动态加载基址,需要将stub的重定位区段(.reloc)修改后保存,将PE重定位信息指针指向该地址
	void ChangeReloc(PCHAR pBuf);

	DWORD GetLastSectionRva();

	//设置OEP
	void setOep(DWORD oepRva);

	//保存加壳后的文件
	bool saveAs(const wchar_t* pName);

	//获取pe文件首地址
	SIZE_T getFileBuff();

	//获取扩展头
	IMAGE_OPTIONAL_HEADER* getOptionHdr();

	//获取NT头
	IMAGE_NT_HEADERS* getNtHdr();
	

	//判断是不是有效的PE文件
	BOOL IsPE();
	


	//BOOL DealwithTLS(PStubConf & pPackInfo);

private:
	//初始化Pe头成员
	void initHeaderMember();
	

//tls表中的信息
private:
	DWORD m_StartOfDataAddress;
	DWORD m_EndOfDataAddress;
	DWORD m_CallBackFuncAddress;

private:
	char* m_pFileBuff;//文件缓冲  PE文件  可以记录前后的pe，后面覆盖前面的
	DWORD m_fileSize;//文件大小
	//添加区段后的PE信息
	char * m_pNewBuf;
	IMAGE_DOS_HEADER*		m_pDos;//dos头
	IMAGE_NT_HEADERS*		m_pNtHdr;//nt头
	IMAGE_FILE_HEADER*		m_pFileHdr;//文件头
	IMAGE_OPTIONAL_HEADER*	m_pOptHdr;//扩展头
	IMAGE_SECTION_HEADER*	m_pScnHdr;//区段表头
};

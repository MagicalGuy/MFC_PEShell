#pragma once
#include <windows.h>
//#include "../stub/stub.h"

class PeFileHandling {
public:
	PeFileHandling();
	~PeFileHandling();

	//ѹ������
	void compress();

	//���ļ�
	bool open(CString pszPath);

	//�ر��ļ����ͷſռ�
	void close();

	// ���һ��������, ���������ε�ͷ������.
	// ������ʧ��,�ͷ���NULL
	//������������  ��������  ���δ�С
	IMAGE_SECTION_HEADER* addSection(char name[8],void* pSectionData,DWORD dwSectionSize);

	// ��һ�ζ��������ݿ���ָ����������
	void setSectioData(IMAGE_SECTION_HEADER* pScn,void* pSectionData,DWORD dwSectionSize);

	// ���ݴ����������,��������ͷ,���������,����NULL
	IMAGE_SECTION_HEADER* getSection(const char* name);

	//�����С
	DWORD calcAligmentSize(DWORD srcSize, DWORD aligment);

	//rvaתfoa
	DWORD RvaToOffset(DWORD rva);

	// ���ط��ŵ�RVA
	DWORD getProcAddress(const char* pszName);

	// �޸�stub���ֵ��ض�λ����
	// ��ַ = ���ػ�ַ + ����RVA + ����ƫ��
	// stub��һ��dll,���Ĵ���Ҫ��dll����ֲ��exe��,Ĭ�ϼ��ػ�ַ�����˸ı�
	// Ȼ��stub��������һ�������α���ֲ��exe�е���������,����RVAҲ������
	// �ı�, ��� , ��Ҫ����Щʹ����VA��ַ�Ĵ�������.
	// 
	void fixStubRva(DWORD oldImageBase, DWORD newImageBase,
		DWORD oldSectionRva, DWORD newSectionRva);



	//�޸�INT
	//void FixINT(PCHAR pBuf);


	//�����ض�λ
	//���ڶ�̬���ػ�ַ,��Ҫ��stub���ض�λ����(.reloc)�޸ĺ󱣴�,��PE�ض�λ��Ϣָ��ָ��õ�ַ
	void ChangeReloc(PCHAR pBuf);

	DWORD GetLastSectionRva();

	//����OEP
	void setOep(DWORD oepRva);

	//����ӿǺ���ļ�
	bool saveAs(const wchar_t* pName);

	//��ȡpe�ļ��׵�ַ
	SIZE_T getFileBuff();

	//��ȡ��չͷ
	IMAGE_OPTIONAL_HEADER* getOptionHdr();

	//��ȡNTͷ
	IMAGE_NT_HEADERS* getNtHdr();
	

	//�ж��ǲ�����Ч��PE�ļ�
	BOOL IsPE();
	


	//BOOL DealwithTLS(PStubConf & pPackInfo);

private:
	//��ʼ��Peͷ��Ա
	void initHeaderMember();
	

//tls���е���Ϣ
private:
	DWORD m_StartOfDataAddress;
	DWORD m_EndOfDataAddress;
	DWORD m_CallBackFuncAddress;

private:
	char* m_pFileBuff;//�ļ�����  PE�ļ�  ���Լ�¼ǰ���pe�����渲��ǰ���
	DWORD m_fileSize;//�ļ���С
	//������κ��PE��Ϣ
	char * m_pNewBuf;
	IMAGE_DOS_HEADER*		m_pDos;//dosͷ
	IMAGE_NT_HEADERS*		m_pNtHdr;//ntͷ
	IMAGE_FILE_HEADER*		m_pFileHdr;//�ļ�ͷ
	IMAGE_OPTIONAL_HEADER*	m_pOptHdr;//��չͷ
	IMAGE_SECTION_HEADER*	m_pScnHdr;//���α�ͷ
};

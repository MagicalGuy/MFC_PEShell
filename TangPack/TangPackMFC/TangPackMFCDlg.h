
// TangPackMFCDlg.h : ͷ�ļ�
//

#pragma once


// CTangPackMFCDlg �Ի���
class CTangPackMFCDlg : public CDialogEx
{
// ����
public:
	CTangPackMFCDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TANGPACKMFC_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CString m_strFilePath;
	afx_msg void OnBnClicked_OpenFile();
	afx_msg void OnBnClicked_Pack();
	afx_msg void OnDropFiles(HDROP hDropInfo);
};

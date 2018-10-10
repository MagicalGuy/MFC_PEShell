
// TangPackMFCDlg.h : 头文件
//

#pragma once


// CTangPackMFCDlg 对话框
class CTangPackMFCDlg : public CDialogEx
{
// 构造
public:
	CTangPackMFCDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TANGPACKMFC_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
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

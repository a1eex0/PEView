#pragma once

#include "framework.h"
#include "PEView.h"


//
// ����: CreateTreeView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
//
// Ŀ��: ���� Tree View ���ƴ�����
//
HWND CreateTreeView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
{
	HWND hwndTV;
	hwndTV = CreateWindowEx(0,
		WC_TREEVIEW,				// ָ���������� Tree View ���ƴ�����
		szWindowName,				// ��������
		// ���ô�����ʽ
		WS_VISIBLE | WS_CHILD | WS_BORDER |
		// ���� Tree View ��ʽ
		TVS_HASBUTTONS | TVS_LINESATROOT | TVS_HASLINES,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		hwndParent,					// �����ھ��
		(HMENU)NULL,				// û�в˵�
		hInst,						// Ӧ�ó���ʵ��
		NULL);						// û��ͼ��

	return hwndTV;
}


//
// ����: AddItemToTree(HWND hwndTV, LPWSTR lpszItem,HTREEITEM hParent,BOOL bFolder)
//
// Ŀ��: ���� Tree View �ڵ�
//
HTREEITEM AddItemToTree(HWND hwndTV,	// ����ͼ���
	LPWSTR lpszItem,					// �ýڵ���ʾ����
	HTREEITEM hParent,					// ���ڵ�����
	BOOL bFolder)						// �Ƿ�����ӽڵ�
{
	TVITEM tvi;
	TVINSERTSTRUCT tvins;
	HTREEITEM hItem;

	// ���� TVITEM ����
	tvi.mask = TVIF_CHILDREN | TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
	// ������ʾ����
	tvi.pszText = lpszItem;
	// �� pszText ��Աָ��Ļ�������С
	tvi.cchTextMax = sizeof(tvi.pszText) / sizeof(tvi.pszText[0]);

	if (bFolder)
	{
		tvi.iImage = 1;
		tvi.iSelectedImage = 2;
		tvi.cChildren = TRUE;		// ָʾ��Ŀ�Ƿ���й�������Ŀ�ı�־��"FALSE"��ʾû������Ŀ��"TRUE"��ʾ��һ����������Ŀ
	}
	else
	{
		tvi.iImage = 3;
		tvi.iSelectedImage = 3;
		tvi.cChildren = FALSE;
	}

	tvins.item = tvi;
	tvins.hInsertAfter = TVI_LAST;	// ָ���²�����ӽڵ�λ�������·���TVI_SORT ��ʾ���ı����� TVI_FIRST ��ʾ�����Ϸ�����

	if (hParent == NULL)
	{
		tvins.hParent = TVI_ROOT;
	}
	else
	{
		tvins.hParent = hParent;
	}

	hItem = TreeView_InsertItem(hwndTV, &tvins);	// ���� TreeView_InsertItem ������½ڵ�

	return hItem;
}

//
// ����: ClearTreeView(HWND hWndTreeView)
//
// Ŀ��: ��� TreeView ������
//
VOID ClearTreeView(HWND hWndTreeView)
{
	TreeView_DeleteAllItems(hWndTreeView);
}



//
//  ����: CreateListView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
//
//  Ŀ��: ���� List View ���ƴ�����
//
HWND CreateListView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
{
	HWND hwndLV;
	hwndLV = CreateWindowEx(0,
		WC_LISTVIEW,				// ָ����������Ϊ List View 
		szWindowName,				// ָ����������
		// ������ʽ
		WS_VISIBLE | WS_CHILD | WS_BORDER |
		// �ؼ���ʽ
		LVS_REPORT | LVS_NOSORTHEADER | HDF_FIXEDWIDTH,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		hwndParent,					// �����ھ��
		(HMENU)NULL,				// �޲˵�
		hInst,						// ��ͼ��
		NULL);
	// һ����Ŀ��ѡ��ʱ������Ŀ������������Ŀ����ͻ����ʾ
	ListView_SetExtendedListViewStyle(hwndLV, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	return hwndLV;
}

//
//  ����: AddListViewColumn(HWND hWndListView, BOOL fmtFlag, WORD wSbuItem, LPWSTR lpColName, DWORD dwLen)
//
//  Ŀ��: ���� List View �ķ���
// 
//  ������fmtFlag:trueΪ���У�falseΪ����룻wSbuItem:����ţ�lpColName:������dwLen:�п�
//
BOOL AddListViewColumn(HWND hWndListView, BOOL fmtFlag, WORD wSbuItem, LPWSTR lpColName, DWORD dwLen)
{
	LVCOLUMN lvc;
	// ���� LVCOLUMN ��Ч��Ա
	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM | LVCFMT_FIXED_WIDTH;
	lvc.iImage = 0;					// ����
	if (fmtFlag)
	{
		lvc.fmt = LVCFMT_CENTER;	// ���뷽ʽ������
	}
	else
	{
		lvc.fmt = LVCFMT_LEFT;		// ���뷽ʽ�������
	}
	lvc.cx = dwLen;					// �п�
	lvc.pszText = lpColName;		// ����
	lvc.iSubItem = wSbuItem;		// �����
	// �������
	if (ListView_InsertColumn(hWndListView, wSbuItem, &lvc) == -1)
	{
		return FALSE;
	}
	return true;
}

//
//  ����: AddListViewRow(HWND hWndListView, DWORD index,DWORD dwAddr)
//
//  Ŀ��: ���� List View ����
//
BOOL AddListViewRow(HWND hWndListView, DWORD index, DWORD dwAddr)
{
	WCHAR szText[9] = L"";

	LVITEM lvI;
	ZeroMemory(&lvI, sizeof(lvI));
	// LVITEM ��Ч��
	lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE;
	lvI.state = 0;			// ��ǰ״̬
	lvI.stateMask = 0;		// ״̬��Ա��λ
	lvI.iItem = index;		// ����
	lvI.iImage = 0;			// ͼ������
	lvI.iSubItem = 0;		// ����������������Ϊ0��
	// ��ȡ��ַ������Ϊ��ʾ����
	_stprintf_s(szText, L"%08X", dwAddr);
	lvI.pszText = szText;
	// ����������
	if (ListView_InsertItem(hWndListView, &lvI) == -1)
	{
		return FALSE;
	}
	return TRUE;
}

//
//  ����:  AddCharData(HWND hWndListView, WORD line, DWORD dwValue, LPWSTR lpFlag)
//
//  Ŀ��: ��ʾ����������������������4�ֽڣ�
//
VOID AddCharData(HWND hWndListView, WORD line, DWORD dwValue, LPWSTR lpFlag)
{
	WCHAR strBuff[5] = L"";

	LVITEM lvI;
	ZeroMemory(&lvI, sizeof(lvI));

	lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE;
	lvI.state = 0;
	lvI.stateMask = 0;
	lvI.iItem = line;
	lvI.iImage = 0;
	lvI.iSubItem = 0;
	lvI.pszText = NULL;
	ListView_InsertItem(hWndListView, &lvI);
	_stprintf_s(strBuff, L"%04X", dwValue);
	ListView_SetItemText(hWndListView, line, 2, strBuff);
	ListView_SetItemText(hWndListView, line, 3, lpFlag);
}

//
//  ����:  AddCharDataL(HWND hWndListView, WORD line, DWORD dwValue, LPWSTR lpFlag)
//
//  Ŀ��: ��ʾ����������������������8�ֽڣ�
//
VOID AddCharDataL(HWND hWndListView, WORD line, DWORD dwValue, LPWSTR lpFlag)
{
	WCHAR strBuff[9] = L"";

	LVITEM lvI;
	ZeroMemory(&lvI, sizeof(lvI));

	lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE;
	lvI.state = 0;
	lvI.stateMask = 0;
	lvI.iItem = line;
	lvI.iImage = 0;
	lvI.iSubItem = 0;
	lvI.pszText = NULL;
	ListView_InsertItem(hWndListView, &lvI);
	_stprintf_s(strBuff, L"%08X", dwValue);
	ListView_SetItemText(hWndListView, line, 2, strBuff);
	ListView_SetItemText(hWndListView, line, 3, lpFlag);
}

//
//  ����: ClearListView(HWND hWndListView)
//
//  Ŀ��: ��� ListView ������
//
VOID ClearListView(HWND hWndListView)
{
	ListView_DeleteAllItems(hWndListView);
	for (int i = 0; i < 4; i++)
	{
		ListView_DeleteColumn(hWndListView, 0);
	}
}



//
//  ����: CreateStatus(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
//
//  Ŀ��: ����״̬����ͼ����
//
HWND CreateStatus(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
{
	HWND hwndST;
	hwndST = CreateWindowEx(0,
		STATUSCLASSNAME,
		szWindowName,
		WS_VISIBLE | WS_CHILD |
		SBT_TOOLTIPS | SBARS_SIZEGRIP,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		hwndParent,
		(HMENU)NULL,
		hInst,
		NULL);

	return hwndST;
}

//
//  ����:  SetStatusText(HWND hWndStatus, LPWSTR szStautusText)
//
//  Ŀ��: ����״̬����ͼ������ʾ����
//
BOOL SetStatusText(HWND hWndStatus, LPWSTR szStautusText)
{
	SendMessage(hWndStatus, SB_SETTEXT, NULL, (long)szStautusText);

	return TRUE;
}
#pragma once

#include "framework.h"
#include "PEView.h"


//
// 函数: CreateTreeView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
//
// 目标: 创建 Tree View 控制窗口类
//
HWND CreateTreeView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
{
	HWND hwndTV;
	hwndTV = CreateWindowEx(0,
		WC_TREEVIEW,				// 指定创建的是 Tree View 控制窗口类
		szWindowName,				// 窗口名称
		// 设置窗口样式
		WS_VISIBLE | WS_CHILD | WS_BORDER |
		// 设置 Tree View 样式
		TVS_HASBUTTONS | TVS_LINESATROOT | TVS_HASLINES,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		hwndParent,					// 父窗口句柄
		(HMENU)NULL,				// 没有菜单
		hInst,						// 应用程序实例
		NULL);						// 没有图标

	return hwndTV;
}


//
// 函数: AddItemToTree(HWND hwndTV, LPWSTR lpszItem,HTREEITEM hParent,BOOL bFolder)
//
// 目标: 增加 Tree View 节点
//
HTREEITEM AddItemToTree(HWND hwndTV,	// 树视图句柄
	LPWSTR lpszItem,					// 该节点显示内容
	HTREEITEM hParent,					// 父节点名称
	BOOL bFolder)						// 是否存在子节点
{
	TVITEM tvi;
	TVINSERTSTRUCT tvins;
	HTREEITEM hItem;

	// 设置 TVITEM 属性
	tvi.mask = TVIF_CHILDREN | TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
	// 设置显示内容
	tvi.pszText = lpszItem;
	// 该 pszText 成员指向的缓冲区大小
	tvi.cchTextMax = sizeof(tvi.pszText) / sizeof(tvi.pszText[0]);

	if (bFolder)
	{
		tvi.iImage = 1;
		tvi.iSelectedImage = 2;
		tvi.cChildren = TRUE;		// 指示项目是否具有关联子项目的标志。"FALSE"表示没有子项目，"TRUE"表示有一个或多个子项目
	}
	else
	{
		tvi.iImage = 3;
		tvi.iSelectedImage = 3;
		tvi.cChildren = FALSE;
	}

	tvins.item = tvi;
	tvins.hInsertAfter = TVI_LAST;	// 指定新插入的子节点位置是最下方，TVI_SORT 表示按文本排序， TVI_FIRST 表示在最上方插入

	if (hParent == NULL)
	{
		tvins.hParent = TVI_ROOT;
	}
	else
	{
		tvins.hParent = hParent;
	}

	hItem = TreeView_InsertItem(hwndTV, &tvins);	// 调用 TreeView_InsertItem 宏插入新节点

	return hItem;
}

//
// 函数: ClearTreeView(HWND hWndTreeView)
//
// 目标: 清空 TreeView 的内容
//
VOID ClearTreeView(HWND hWndTreeView)
{
	TreeView_DeleteAllItems(hWndTreeView);
}



//
//  函数: CreateListView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
//
//  目标: 创建 List View 控制窗口类
//
HWND CreateListView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
{
	HWND hwndLV;
	hwndLV = CreateWindowEx(0,
		WC_LISTVIEW,				// 指定窗口类行为 List View 
		szWindowName,				// 指定窗口名称
		// 窗口样式
		WS_VISIBLE | WS_CHILD | WS_BORDER |
		// 控件样式
		LVS_REPORT | LVS_NOSORTHEADER | HDF_FIXEDWIDTH,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		hwndParent,					// 父窗口句柄
		(HMENU)NULL,				// 无菜单
		hInst,						// 无图标
		NULL);
	// 一个项目被选中时，该项目及其所有子项目都将突出显示
	ListView_SetExtendedListViewStyle(hwndLV, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	return hwndLV;
}

//
//  函数: AddListViewColumn(HWND hWndListView, BOOL fmtFlag, WORD wSbuItem, LPWSTR lpColName, DWORD dwLen)
//
//  目标: 创建 List View 的分列
// 
//  参数：fmtFlag:true为居中，false为左对齐；wSbuItem:列序号；lpColName:列名；dwLen:列宽
//
BOOL AddListViewColumn(HWND hWndListView, BOOL fmtFlag, WORD wSbuItem, LPWSTR lpColName, DWORD dwLen)
{
	LVCOLUMN lvc;
	// 设置 LVCOLUMN 有效成员
	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM | LVCFMT_FIXED_WIDTH;
	lvc.iImage = 0;					// 索引
	if (fmtFlag)
	{
		lvc.fmt = LVCFMT_CENTER;	// 对齐方式：居中
	}
	else
	{
		lvc.fmt = LVCFMT_LEFT;		// 对齐方式：左对齐
	}
	lvc.cx = dwLen;					// 列宽
	lvc.pszText = lpColName;		// 列名
	lvc.iSubItem = wSbuItem;		// 列序号
	// 插入分列
	if (ListView_InsertColumn(hWndListView, wSbuItem, &lvc) == -1)
	{
		return FALSE;
	}
	return true;
}

//
//  函数: AddListViewRow(HWND hWndListView, DWORD index,DWORD dwAddr)
//
//  目标: 增加 List View 的行
//
BOOL AddListViewRow(HWND hWndListView, DWORD index, DWORD dwAddr)
{
	WCHAR szText[9] = L"";

	LVITEM lvI;
	ZeroMemory(&lvI, sizeof(lvI));
	// LVITEM 有效项
	lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE;
	lvI.state = 0;			// 当前状态
	lvI.stateMask = 0;		// 状态成员的位
	lvI.iItem = index;		// 索引
	lvI.iImage = 0;			// 图标索引
	lvI.iSubItem = 0;		// 子项索引（无子项为0）
	// 获取地址并设置为显示内容
	_stprintf_s(szText, L"%08X", dwAddr);
	lvI.pszText = szText;
	// 插入项内容
	if (ListView_InsertItem(hWndListView, &lvI) == -1)
	{
		return FALSE;
	}
	return TRUE;
}

//
//  函数:  AddCharData(HWND hWndListView, WORD line, DWORD dwValue, LPWSTR lpFlag)
//
//  目标: 显示特征码所包含的子项结果（4字节）
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
//  函数:  AddCharDataL(HWND hWndListView, WORD line, DWORD dwValue, LPWSTR lpFlag)
//
//  目标: 显示特征码所包含的子项结果（8字节）
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
//  函数: ClearListView(HWND hWndListView)
//
//  目标: 清空 ListView 的内容
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
//  函数: CreateStatus(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName)
//
//  目标: 创建状态栏视图窗口
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
//  函数:  SetStatusText(HWND hWndStatus, LPWSTR szStautusText)
//
//  目标: 设置状态栏视图窗口显示内容
//
BOOL SetStatusText(HWND hWndStatus, LPWSTR szStautusText)
{
	SendMessage(hWndStatus, SB_SETTEXT, NULL, (long)szStautusText);

	return TRUE;
}
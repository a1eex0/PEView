#pragma once

#include "resource.h"

// 声明其他文件中已定义的全局变量
extern HWND hwndTreeView, hwndListView, hwndStatus;    // 控件句柄
extern LPVOID lpFileBuffer; // 文件缓冲区
extern LPWSTR szFileName;	// 文件名
extern DWORD dwFileLength;	// 文件长度

// Common.cpp
// “打开”文件对话框，选取需要查看的PE文件
LPWSTR OpenFileName(HWND hWnd, LPWSTR lpFilePath);
// 文件处理主程序
VOID FileMain(HWND hWnd, LPWSTR lpFilePath);
// 树视图单击响应
VOID OnClickTree(LPNMHDR lPhr);
// 列表视图显示十六进制内容
VOID HextoList(PCHAR buffer, DWORD dwStart, DWORD dwReadLength);
// 从相对虚拟地址到文件偏移的计算
DWORD RvaToOffset(DWORD dwRva, PCHAR buffer);



// Controls.cpp
// 树视图相关函数
// 创建 Tree View 控制窗口类
HWND CreateTreeView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName);
// 增加 Tree View 节点
HTREEITEM AddItemToTree(HWND hwndTV, LPWSTR lpszItem, HTREEITEM hParent, BOOL bFolder);
// 清空 TreeView 的内容
VOID ClearTreeView(HWND hWndTreeView);
// 列表视图相关函数
// 创建 List View 控制窗口类
HWND CreateListView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName);
// 创建 List View 的分列
BOOL AddListViewColumn(HWND hWndListView, BOOL fmtFlag, WORD wSbuItem, LPWSTR lpColName, DWORD dwLen);
// 增加 List View 的行
BOOL AddListViewRow(HWND hWndListView, DWORD index, DWORD dwAddr);
// 显示特征码所包含的子项结果（4字节）
VOID AddCharData(HWND hWndListView, WORD line, DWORD dwValue, LPWSTR lpFlag);
// 显示特征码所包含的子项结果（8字节）
VOID AddCharDataL(HWND hWndListView, WORD line, DWORD dwValue, LPWSTR lpFlag);
// 清空 ListView 的内容
VOID ClearListView(HWND hWndListView);
// 状态栏视图相关函数
// 创建状态栏视图窗口
HWND CreateStatus(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName);
// 设置状态栏视图窗口显示内容
BOOL SetStatusText(HWND hWndStatus, LPWSTR szStautusText);


// PEFormat64.cpp
// PE64文件处理主程序
VOID FormatMain64(HWND hWnd, PCHAR buffer, LPWSTR lpFilePath);
// PE64文件树视图点击对应列表视图内容显示
VOID TreeToList64(PCHAR buffer, LPWSTR szText, LPWSTR lpFilePath);


// PEFormat32.cpp
// PE32文件处理主程序
VOID FormatMain32(HWND hWnd, PCHAR buffer, LPWSTR lpFilePath);
// PE32文件树视图点击对应列表视图内容显示
VOID TreeToList32(PCHAR buffer, LPWSTR szText, LPWSTR lpFilePath);

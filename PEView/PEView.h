#pragma once

#include "resource.h"

// ���������ļ����Ѷ����ȫ�ֱ���
extern HWND hwndTreeView, hwndListView, hwndStatus;    // �ؼ����
extern LPVOID lpFileBuffer; // �ļ�������
extern LPWSTR szFileName;	// �ļ���
extern DWORD dwFileLength;	// �ļ�����

// Common.cpp
// ���򿪡��ļ��Ի���ѡȡ��Ҫ�鿴��PE�ļ�
LPWSTR OpenFileName(HWND hWnd, LPWSTR lpFilePath);
// �ļ�����������
VOID FileMain(HWND hWnd, LPWSTR lpFilePath);
// ����ͼ������Ӧ
VOID OnClickTree(LPNMHDR lPhr);
// �б���ͼ��ʾʮ����������
VOID HextoList(PCHAR buffer, DWORD dwStart, DWORD dwReadLength);
// ����������ַ���ļ�ƫ�Ƶļ���
DWORD RvaToOffset(DWORD dwRva, PCHAR buffer);



// Controls.cpp
// ����ͼ��غ���
// ���� Tree View ���ƴ�����
HWND CreateTreeView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName);
// ���� Tree View �ڵ�
HTREEITEM AddItemToTree(HWND hwndTV, LPWSTR lpszItem, HTREEITEM hParent, BOOL bFolder);
// ��� TreeView ������
VOID ClearTreeView(HWND hWndTreeView);
// �б���ͼ��غ���
// ���� List View ���ƴ�����
HWND CreateListView(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName);
// ���� List View �ķ���
BOOL AddListViewColumn(HWND hWndListView, BOOL fmtFlag, WORD wSbuItem, LPWSTR lpColName, DWORD dwLen);
// ���� List View ����
BOOL AddListViewRow(HWND hWndListView, DWORD index, DWORD dwAddr);
// ��ʾ����������������������4�ֽڣ�
VOID AddCharData(HWND hWndListView, WORD line, DWORD dwValue, LPWSTR lpFlag);
// ��ʾ����������������������8�ֽڣ�
VOID AddCharDataL(HWND hWndListView, WORD line, DWORD dwValue, LPWSTR lpFlag);
// ��� ListView ������
VOID ClearListView(HWND hWndListView);
// ״̬����ͼ��غ���
// ����״̬����ͼ����
HWND CreateStatus(HINSTANCE hInst, HWND hwndParent, LPWSTR szWindowName);
// ����״̬����ͼ������ʾ����
BOOL SetStatusText(HWND hWndStatus, LPWSTR szStautusText);


// PEFormat64.cpp
// PE64�ļ�����������
VOID FormatMain64(HWND hWnd, PCHAR buffer, LPWSTR lpFilePath);
// PE64�ļ�����ͼ�����Ӧ�б���ͼ������ʾ
VOID TreeToList64(PCHAR buffer, LPWSTR szText, LPWSTR lpFilePath);


// PEFormat32.cpp
// PE32�ļ�����������
VOID FormatMain32(HWND hWnd, PCHAR buffer, LPWSTR lpFilePath);
// PE32�ļ�����ͼ�����Ӧ�б���ͼ������ʾ
VOID TreeToList32(PCHAR buffer, LPWSTR szText, LPWSTR lpFilePath);

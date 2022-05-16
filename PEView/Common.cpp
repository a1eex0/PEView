#pragma once

#include "framework.h"
#include "PEView.h"

#pragma warning(disable:4996)

// ȫ�ֱ���:
LPWSTR szFileName;
DWORD PETypeFlag;
DWORD dwFileLength;
PCHAR pFileBuffer;

// �˴���ģ���а����ĺ�����ǰ������:


//
//  ����: OpenFileName(HWND hWnd, LPWSTR lpFilePath)
//
//  Ŀ��: ���򿪡��ļ��Ի���ѡȡ��Ҫ�鿴��PE�ļ�
//
LPWSTR OpenFileName(HWND hWnd, LPWSTR lpFilePath)
{
    LPWSTR szFilePathName = lpFilePath;     // ����洢�ļ�·�����ַ�����
    OPENFILENAME file = { 0 };              // ����һ���յ� OPENFILENAME ����
    file.lStructSize = sizeof(file);        // ����ṹ��С���������ȶ���
    file.hwndOwner = hWnd;                  // �����������ڵľ��
    file.lpstrFile = szFilePathName;        // ����ȫ·���ļ����Ĵ洢������
    file.nMaxFile = MAX_PATH;               // ����ȫ·���ļ����������ĳ���
    // �ļ�ɸѡ�������ַ������������ʹ��";"���������Ӧ����"\0\0"��β���ṹΪ��"��ʾ"\0"ѡȡ����"\0"��ʾ"\0"ѡȡ����"\0\0
    file.lpstrFilter = L"PE Files(*.exe;*.dll;*.sys;*.obj)\0*.exe;*.dll;*.sys;*.obj\0All Files(*.*)\0*.*\0\0";
    GetOpenFileName(&file);                 // ���� GetOpenFileName ������ file ���ô򿪶Ի���ѡȡ�ļ�

    return lpFilePath;
}

//
//  ����: FileMain(HWND hWnd, LPWSTR lpFilePath)
//
//  Ŀ��: �ļ�����������
//
VOID FileMain(HWND hWnd, LPWSTR lpFilePath)
{
    if (!lpFilePath)
    {
        return;
    }
    FILE* pFile = NULL;
    // PCHAR pFileBuffer;
    pFile = _wfopen(lpFilePath,L"rb");                  // ���ļ�
    fseek(pFile, 0, SEEK_END);	                        // ��λ��ָ���ƶ����ļ�ĩβ��SEEK_END ��ʾĩβ��
    dwFileLength = ftell(pFile);	                        // ��ȡ��ǰλ��ָ��������ļ��׵�ƫ���ֽ������Դ˻�ȡ�ļ������ֽ���
    rewind(pFile);	                                    // ��λ��ָ���ƶ����ļ���ͷ
    int imageLength = dwFileLength * sizeof(char) + 1;	// �� char �ͼ��㳤�ȣ��������Ŀսض�
    pFileBuffer = (char*)malloc(imageLength);	        // ��̬�����ڴ�ռ�
    memset(pFileBuffer, 0, dwFileLength * sizeof(char) + 1);	// �� buffer �ռ��ÿ�
    fread(pFileBuffer, 1, imageLength, pFile);	        // �� pFile �ļ������ֽڶ�ȡ�� fileBuffer ��

    szFileName = PathFindFileName(lpFilePath);
    // ���ڴ��л�ȡ�ļ�������Ϣ
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;	                    // ��������ֵ DOS ͷ
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pFileBuffer);   // ��������ֵ NT ͷ
    // �ж� NT Signature �Ƿ�Ϊ PE
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
    {
        MessageBox(hWnd, L"�ⲻ��һ�� PE �ļ���", L"����", MB_OK| MB_ICONWARNING);
        return;
    }
    PETypeFlag = pNt->OptionalHeader.Magic;
    // ���� OptionalHeader ��ʶ���ж� PE �ļ��ṹ
    if (PETypeFlag == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        FormatMain32(hWnd, pFileBuffer, lpFilePath);
    }
    else if (PETypeFlag == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        FormatMain64(hWnd, pFileBuffer, lpFilePath);
    }
    else
    {
        MessageBox(hWnd, L"�ݲ�֧�ָ��ļ��Ľ�����", L"��Ǹ", MB_OK);
        return;
    }
}

//
//  ����: OnClickTree(LPNMHDR lPhr)
//
//  Ŀ��: ����ͼ������Ӧ
//
VOID OnClickTree(LPNMHDR lPhr)
{
    POINT point;
    TVHITTESTINFO thti;
    HTREEITEM htItem;
    TVITEM tvi;
    // ��ȡ���λ��
    GetCursorPos(&point);
    // ��������� Client �����λ��
    ScreenToClient(hwndTreeView, &point);
    // ��� TVHITTESTINFO �ṹ
    thti.pt = point;
    thti.flags = TVHT_TORIGHT;

    // �Ƿ񵥻��ӽڵ㣬���򷵻ؽڵ���
    htItem = TreeView_HitTest(hwndTreeView, &thti);

    if (htItem != NULL)
    {
        // ���� TVITEM �ṹ
        WCHAR szText[40];
        memset(&tvi, 0, sizeof(tvi));
        tvi.mask = TVIF_TEXT | TVIF_PARAM;
        tvi.hItem = htItem;
        tvi.pszText = szText;
        tvi.cchTextMax = sizeof(szText);
        // ����������ӽڵ�Ĳ�������
        TreeView_GetItem(hwndTreeView, &tvi);
        // ���ݱ�����ӽڵ�����ƽ�����Ӧ
        if (PETypeFlag == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            TreeToList32(pFileBuffer, szText, szFileName);
        }
        else if (PETypeFlag == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            TreeToList64(pFileBuffer, szText, szFileName);
        }
        
    }
}

//
//  ����: HextoList(HANDLE hFilePointer, DWORD dwStartAddr, LARGE_INTEGER liFileSize)
//
//  Ŀ��: �б���ͼ��ʾʮ����������
//
VOID HextoList(PCHAR buffer, DWORD dwStart, DWORD dwReadLength)
{
    DWORD dwLineNum = 0;
    DWORD dwReadNum = 0;
    WCHAR hexBuffer[49] = L"";
    WCHAR strBuffer[4] = L"";
    WCHAR asciiBuffer[17] = L"";
    PCHAR pFileBuffer = buffer + dwStart;

    // �����б���
    AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
    AddListViewColumn(hwndListView, 0, 1, L"Raw Data", 396);
    AddListViewColumn(hwndListView, 1, 2, L"Value", 140);
    // ��ʼ��������ļ�����
    while (TRUE)
    {
        // ��ʾ�к�
        AddListViewRow(hwndListView, dwLineNum, dwStart);
        // 16λһ��
        int i;
        for (i = 0; i < 16; i++)
        {
            _stprintf_s(strBuffer, L"%02X ", (unsigned char)pFileBuffer[i]);
            wcscat_s(hexBuffer, strBuffer);
            dwReadNum += 1;
            if (dwReadNum == dwReadLength)
            {
                i++;
                break;
            }
        }
        // ����б���
        ListView_SetItemText(hwndListView, dwLineNum, 1, hexBuffer);
        // ��ջ���������
        wcscpy_s(hexBuffer, L"");
        for (size_t n = 0; n < i; n++)
        {
            if (pFileBuffer[n] >= 32 && pFileBuffer[n] <= 126)
            {
                _stprintf_s(strBuffer, L"%c", WCHAR(pFileBuffer[n]));
            }
            else
            {
                _stprintf_s(strBuffer, L".");
            }
            wcscat_s(asciiBuffer, strBuffer);
        }
        ListView_SetItemText(hwndListView, dwLineNum, 2, asciiBuffer);
        // ��ջ���������
        wcscpy_s(asciiBuffer, L"");
        dwLineNum += 1;
        dwStart += 16;
        pFileBuffer += 16;

        if (dwReadNum == dwReadLength)
        {
            break;
        }
    }
}

//
//  ����: RvaToOffset(DWORD dwRva, PCHAR buffer)
//
//  Ŀ��: ����������ַ���ļ�ƫ�Ƶļ���
//
DWORD RvaToOffset(DWORD dwRva, PCHAR buffer)
{
    // DOS ͷ
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
    // NT ͷ
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(buffer + pDos->e_lfanew);
    // ����ͷ
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    // �ж��Ƿ��ڽ���ͷ��
    if (dwRva < pSection[0].VirtualAddress)
    {
        return dwRva;
    }
    // ���ݽ����μ���ƫ��
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        if (dwRva >= pSection[i].VirtualAddress && dwRva <= (pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize))
        {
            return dwRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
        }
    }
}




















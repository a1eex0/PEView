#pragma once

#include "framework.h"
#include "PEView.h"

#pragma warning(disable:4996)

// 全局变量:
LPWSTR szFileName;
DWORD PETypeFlag;
DWORD dwFileLength;
PCHAR pFileBuffer;

// 此代码模块中包含的函数的前向声明:


//
//  函数: OpenFileName(HWND hWnd, LPWSTR lpFilePath)
//
//  目标: “打开”文件对话框，选取需要查看的PE文件
//
LPWSTR OpenFileName(HWND hWnd, LPWSTR lpFilePath)
{
    LPWSTR szFilePathName = lpFilePath;     // 定义存储文件路径的字符数组
    OPENFILENAME file = { 0 };              // 定义一个空的 OPENFILENAME 类型
    file.lStructSize = sizeof(file);        // 定义结构大小，必须优先定义
    file.hwndOwner = hWnd;                  // 定义所属窗口的句柄
    file.lpstrFile = szFilePathName;        // 定义全路径文件名的存储缓冲区
    file.nMaxFile = MAX_PATH;               // 定义全路径文件名缓冲区的长度
    // 文件筛选的类型字符串，多个类型使用";"隔开，最后应当以"\0\0"结尾。结构为："显示"\0"选取类型"\0"显示"\0"选取类型"\0\0
    file.lpstrFilter = L"PE Files(*.exe;*.dll;*.sys;*.obj)\0*.exe;*.dll;*.sys;*.obj\0All Files(*.*)\0*.*\0\0";
    GetOpenFileName(&file);                 // 调用 GetOpenFileName 函数以 file 配置打开对话框选取文件

    return lpFilePath;
}

//
//  函数: FileMain(HWND hWnd, LPWSTR lpFilePath)
//
//  目标: 文件处理主程序
//
VOID FileMain(HWND hWnd, LPWSTR lpFilePath)
{
    if (!lpFilePath)
    {
        return;
    }
    FILE* pFile = NULL;
    // PCHAR pFileBuffer;
    pFile = _wfopen(lpFilePath,L"rb");                  // 打开文件
    fseek(pFile, 0, SEEK_END);	                        // 将位置指针移动到文件末尾（SEEK_END 表示末尾）
    dwFileLength = ftell(pFile);	                        // 获取当前位置指针相对于文件首的偏移字节数，以此获取文件的总字节数
    rewind(pFile);	                                    // 将位置指针移动到文件开头
    int imageLength = dwFileLength * sizeof(char) + 1;	// 按 char 型计算长度，增加最后的空截断
    pFileBuffer = (char*)malloc(imageLength);	        // 动态申请内存空间
    memset(pFileBuffer, 0, dwFileLength * sizeof(char) + 1);	// 将 buffer 空间置空
    fread(pFileBuffer, 1, imageLength, pFile);	        // 将 pFile 文件流逐字节读取到 fileBuffer 中

    szFileName = PathFindFileName(lpFilePath);
    // 从内存中获取文件基本信息
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;	                    // 声明并赋值 DOS 头
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pFileBuffer);   // 声明并赋值 NT 头
    // 判断 NT Signature 是否为 PE
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
    {
        MessageBox(hWnd, L"这不是一个 PE 文件！", L"警告", MB_OK| MB_ICONWARNING);
        return;
    }
    PETypeFlag = pNt->OptionalHeader.Magic;
    // 根据 OptionalHeader 标识，判断 PE 文件结构
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
        MessageBox(hWnd, L"暂不支持该文件的解析！", L"抱歉", MB_OK);
        return;
    }
}

//
//  函数: OnClickTree(LPNMHDR lPhr)
//
//  目标: 树视图单击响应
//
VOID OnClickTree(LPNMHDR lPhr)
{
    POINT point;
    TVHITTESTINFO thti;
    HTREEITEM htItem;
    TVITEM tvi;
    // 获取鼠标位置
    GetCursorPos(&point);
    // 计算相对于 Client 的鼠标位置
    ScreenToClient(hwndTreeView, &point);
    // 填充 TVHITTESTINFO 结构
    thti.pt = point;
    thti.flags = TVHT_TORIGHT;

    // 是否单击子节点，是则返回节点句柄
    htItem = TreeView_HitTest(hwndTreeView, &thti);

    if (htItem != NULL)
    {
        // 声明 TVITEM 结构
        WCHAR szText[40];
        memset(&tvi, 0, sizeof(tvi));
        tvi.mask = TVIF_TEXT | TVIF_PARAM;
        tvi.hItem = htItem;
        tvi.pszText = szText;
        tvi.cchTextMax = sizeof(szText);
        // 检索被点击子节点的部分属性
        TreeView_GetItem(hwndTreeView, &tvi);
        // 根据被点击子节点的名称进行响应
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
//  函数: HextoList(HANDLE hFilePointer, DWORD dwStartAddr, LARGE_INTEGER liFileSize)
//
//  目标: 列表视图显示十六进制内容
//
VOID HextoList(PCHAR buffer, DWORD dwStart, DWORD dwReadLength)
{
    DWORD dwLineNum = 0;
    DWORD dwReadNum = 0;
    WCHAR hexBuffer[49] = L"";
    WCHAR strBuffer[4] = L"";
    WCHAR asciiBuffer[17] = L"";
    PCHAR pFileBuffer = buffer + dwStart;

    // 设置列标题
    AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
    AddListViewColumn(hwndListView, 0, 1, L"Raw Data", 396);
    AddListViewColumn(hwndListView, 1, 2, L"Value", 140);
    // 开始遍历输出文件内容
    while (TRUE)
    {
        // 显示行号
        AddListViewRow(hwndListView, dwLineNum, dwStart);
        // 16位一行
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
        // 填充列表项
        ListView_SetItemText(hwndListView, dwLineNum, 1, hexBuffer);
        // 清空缓冲区数据
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
        // 清空缓冲区数据
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
//  函数: RvaToOffset(DWORD dwRva, PCHAR buffer)
//
//  目标: 从相对虚拟地址到文件偏移的计算
//
DWORD RvaToOffset(DWORD dwRva, PCHAR buffer)
{
    // DOS 头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
    // NT 头
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(buffer + pDos->e_lfanew);
    // 节区头
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    // 判断是否在节区头内
    if (dwRva < pSection[0].VirtualAddress)
    {
        return dwRva;
    }
    // 根据节区段计算偏移
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        if (dwRva >= pSection[i].VirtualAddress && dwRva <= (pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize))
        {
            return dwRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
        }
    }
}




















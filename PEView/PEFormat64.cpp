#pragma once

#include "framework.h"
#include "PEView.h"


// 此代码模块中包含的函数的前向声明:
VOID InitTreeView64(PCHAR buffer, LPWSTR lpFileName);
VOID InitListView64(PCHAR buffer, DWORD dwStart, DWORD dwReadLength);


//
//  函数: FormatMain64(HWND hWnd, PCHAR buffer, LPWSTR lpFilePath)
//
//  目标: PE64文件处理主程序
//
VOID FormatMain64(HWND hWnd, PCHAR buffer, LPWSTR lpFilePath)
{
	MessageBox(hwndListView, L"这是一个 PE64/PE32+ 程序！", L"提示", MB_OK);
	InitTreeView64(buffer, szFileName);
	/*InitListView64(buffer,0,dwFileLength);*/
	SetStatusText(hwndStatus, szFileName);
}

//
//  函数: InitTreeView64(PCHAR buffer, LPWSTR lpFileName)
//
//  目标: 设置树视图显示内容
//
VOID InitTreeView64(PCHAR buffer, LPWSTR lpFileName)
{
	HTREEITEM hRoot, hDosHeader, hNTHeaders, hNTSignature, hNTFileHeader, hNTOptionalHeader, hSectionHeaders, hSection;
	WCHAR strSectionName[100];
	WCHAR strNameBuffer[100];
	WCHAR* DataDirName[0xF] = {
		L"IMAGE_EXPORT_DIRECTORY",
		L"IMAGE_IMPORT_DIRECTORY",
		L"IMAGE_RESOURCE_DIRECTORY",
		L"IMAGE_EXCEPTION_DIRECTORY",
		L"IMAGE_CERTIFICATE_DIRECTORY",
		L"IMAGE_BASE_RELOC_DIRECTORY",
		L"IMAGE_DEBUG_DIRECTORY",
		L"IMAGE_ARCHITECTURE_DIRECTORY",
		L"IMAGE_GLOBALPTR_DIRECTORY",
		L"IMAGE_TLS_DIRECTORY",
		L"IMAGE_LOAD_CONFIG_DIRECTORY",
		L"IMAGE_BOUND_IMPORT_DIRECTORY",
		L"IMAGE_IAT_DIRECTORY",
		L"IMAGE_DELAY_IMPORT_DIRECTORY",
		L"IMAGE_COM_DESCRIPTOR_DIRECTORY"
	};
	BOOL bCertFlag = FALSE;

	// 添加树视图的根节点
	hRoot = AddItemToTree(hwndTreeView, lpFileName, NULL, TRUE);
	// 添加 Dos 头节点
	hDosHeader = AddItemToTree(hwndTreeView, L"IMAGE_DOS_HEADER", hRoot, FALSE);
	// 添加 NT 头节点
	hNTHeaders = AddItemToTree(hwndTreeView, L"IMAGE_NT_HEADERS64", hRoot, TRUE);
	// 为 NT 头添加子节点
	hNTSignature = AddItemToTree(hwndTreeView, L"NT Signature", hNTHeaders, FALSE);
	hNTFileHeader = AddItemToTree(hwndTreeView, L"IMAGE_FILE_HEADER", hNTHeaders, FALSE);
	hNTOptionalHeader = AddItemToTree(hwndTreeView, L"IMAGE_OPTIONAL_HEADER64", hNTHeaders, FALSE);
	// 添加 Section 节点
	hSectionHeaders = AddItemToTree(hwndTreeView, L"IMAGE_SECTION_HEADERS", hRoot, TRUE);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_DATA_DIRECTORY pBoundDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
	if (pBoundDir->VirtualAddress != 0)
	{
		AddItemToTree(hwndTreeView, L"IMAGE_BOUND_IMPORT_DIRECTORY", hRoot, FALSE);
	}

	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		// 将 PBYTE 转化为 LPWSTR
		memset(strSectionName, 0, sizeof(strSectionName));
		MultiByteToWideChar(CP_ACP, 0, (PCHAR)pSection[i].Name, strlen((PCHAR)pSection[i].Name) + 1, strSectionName, sizeof(strSectionName) / sizeof(strSectionName[0]));
		// 添加 Section 子节点
		AddItemToTree(hwndTreeView, strSectionName, hSectionHeaders, FALSE);

		// 拼接节区在树视图中的显示内容
		wcscpy_s(strNameBuffer, L"SECTION");
		wcscat_s(strNameBuffer, strSectionName);

		BOOL bTableinSection = FALSE;
		BOOL bTableNum[0xF];
		// 判断表目录是否在当前节区
		for (int n = 0; n < 0xF; n++)
		{
			PIMAGE_DATA_DIRECTORY pDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + n);
			if ((pDir->Size!=0)&&(pDir->VirtualAddress>=pSection[i].VirtualAddress)&&(pDir->VirtualAddress<(pSection[i].VirtualAddress+pSection[i].Misc.VirtualSize)))
			{
				bTableinSection = TRUE;
				bTableNum[n] = TRUE;
			}
			else
			{
				bTableNum[n] = FALSE;
			}
		}
		if (bTableinSection)
		{
			// 添加该子节点在树视图根列表下
			hSection = AddItemToTree(hwndTreeView, strNameBuffer, hRoot, TRUE);
			for (int n = 0; n < 0xF; n++)
			{
				if (bTableNum[n] == TRUE)
				{
					if (n == 4)
					{
						bCertFlag = TRUE;
						continue;
					}
					AddItemToTree(hwndTreeView, DataDirName[n], hSection, FALSE);
				}
			}
			TreeView_Expand(hwndTreeView, hSection, TVE_EXPAND);
		}
		else
		{
			hSection = AddItemToTree(hwndTreeView, strNameBuffer, hRoot, FALSE);
		}
	}
	if (bCertFlag)
	{
		AddItemToTree(hwndTreeView, DataDirName[4], hRoot, FALSE);
	}
	// 将节点设置为展开
	TreeView_Expand(hwndTreeView, hRoot, TVE_EXPAND);
	TreeView_Expand(hwndTreeView, hNTHeaders, TVE_EXPAND);
	TreeView_Expand(hwndTreeView, hSectionHeaders, TVE_EXPAND);
}

//
//  函数: InitListView64(PCHAR buffer, DWORD dwStart, DWORD dwReadLength)
//
//  目标: 设置列表视图显示文件十六进制内容
//
VOID InitListView64(PCHAR buffer, DWORD dwStart, DWORD dwReadLength)
{
	HextoList(buffer, dwStart, dwReadLength);
}

//
//  函数: CLICK_IMAGE_DOS_HEADER64(PCHAR buffer)
//
//  目标: DOS 头列表显示函数
//
VOID CLICK_IMAGE_DOS_HEADER64(PCHAR buffer)
{
	WCHAR strBuffer[9];
	// 添加分列
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 250);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 200);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;

	AddListViewRow(hwndListView, 0, 0);
	_stprintf_s(strBuffer, L"%04X", pDos->e_magic);
	ListView_SetItemText(hwndListView, 0, 1, strBuffer);
	ListView_SetItemText(hwndListView, 0, 2, L"DOS 签名");
	_stprintf_s(strBuffer, L"%c%c", WCHAR(pDos->e_magic&0xFF),WCHAR(pDos->e_magic>>8));
	ListView_SetItemText(hwndListView, 0, 3, strBuffer);
		
	AddListViewRow(hwndListView, 1, 2);
	_stprintf_s(strBuffer, L"%04X", pDos->e_cblp);
	ListView_SetItemText(hwndListView, 1, 1, strBuffer);
	ListView_SetItemText(hwndListView, 1, 2, L"文件最后一页的字节数");

	AddListViewRow(hwndListView, 2, 4);
	_stprintf_s(strBuffer, L"%04X", pDos->e_cp);
	ListView_SetItemText(hwndListView, 2, 1, strBuffer);
	ListView_SetItemText(hwndListView, 2, 2, L"文件中的页面");

	AddListViewRow(hwndListView, 3, 6);
	_stprintf_s(strBuffer, L"%04X", pDos->e_crlc);
	ListView_SetItemText(hwndListView, 3, 1, strBuffer);
	ListView_SetItemText(hwndListView, 3, 2, L"重定位");

	AddListViewRow(hwndListView, 4, 8);
	_stprintf_s(strBuffer, L"%04X", pDos->e_cparhdr);
	ListView_SetItemText(hwndListView, 4, 1, strBuffer);
	ListView_SetItemText(hwndListView, 4, 2, L"段落标题的大小");

	AddListViewRow(hwndListView, 5, 10);
	_stprintf_s(strBuffer, L"%04X", pDos->e_minalloc);
	ListView_SetItemText(hwndListView, 5, 1, strBuffer);
	ListView_SetItemText(hwndListView, 5, 2, L"最少需要额外的段落");

	AddListViewRow(hwndListView, 6, 12);
	_stprintf_s(strBuffer, L"%04X", pDos->e_maxalloc);
	ListView_SetItemText(hwndListView, 6, 1, strBuffer);
	ListView_SetItemText(hwndListView, 6, 2, L"最多需要额外的段落");

	AddListViewRow(hwndListView, 7, 14);
	_stprintf_s(strBuffer, L"%04X", pDos->e_ss);
	ListView_SetItemText(hwndListView, 7, 1, strBuffer);
	ListView_SetItemText(hwndListView, 7, 2, L"初始（相对）SS 值");

	AddListViewRow(hwndListView, 8, 16);
	_stprintf_s(strBuffer, L"%04X", pDos->e_sp);
	ListView_SetItemText(hwndListView, 8, 1, strBuffer);
	ListView_SetItemText(hwndListView, 8, 2, L"初始 SP 值");

	AddListViewRow(hwndListView, 9, 18);
	_stprintf_s(strBuffer, L"%04X", pDos->e_csum);
	ListView_SetItemText(hwndListView, 9, 1, strBuffer);
	ListView_SetItemText(hwndListView, 9, 2, L"校验和");

	AddListViewRow(hwndListView, 10, 20);
	_stprintf_s(strBuffer, L"%04X", pDos->e_ip);
	ListView_SetItemText(hwndListView, 10, 1, strBuffer);
	ListView_SetItemText(hwndListView, 10, 2, L"初始 IP 值");

	AddListViewRow(hwndListView, 11, 22);
	_stprintf_s(strBuffer, L"%04X", pDos->e_cs);
	ListView_SetItemText(hwndListView, 11, 1, strBuffer);
	ListView_SetItemText(hwndListView, 11, 2, L"初始（相对）CS 值");

	AddListViewRow(hwndListView, 12, 24);
	_stprintf_s(strBuffer, L"%04X", pDos->e_lfarlc);
	ListView_SetItemText(hwndListView, 12, 1, strBuffer);
	ListView_SetItemText(hwndListView, 12, 2, L"重定位表的文件地址");

	AddListViewRow(hwndListView, 13, 26);
	_stprintf_s(strBuffer, L"%04X", pDos->e_ovno);
	ListView_SetItemText(hwndListView, 13, 1, strBuffer);
	ListView_SetItemText(hwndListView, 13, 2, L"叠加编号");

	AddListViewRow(hwndListView, 14, 28);
	ListView_SetItemText(hwndListView, 14, 1, L"e_res[4]");
	ListView_SetItemText(hwndListView, 14, 2, L"保留字（8字节）");

	AddListViewRow(hwndListView, 15, 36);
	_stprintf_s(strBuffer, L"%04X", pDos->e_oemid);
	ListView_SetItemText(hwndListView, 15, 1, strBuffer);
	ListView_SetItemText(hwndListView, 15, 2, L"OEM 标识符（用于 e_oeminfo）");

	AddListViewRow(hwndListView, 16, 38);
	_stprintf_s(strBuffer, L"%04X", pDos->e_oeminfo);
	ListView_SetItemText(hwndListView, 16, 1, strBuffer);
	ListView_SetItemText(hwndListView, 16, 2, L"OEM 信息；e_oemid 特定的");

	AddListViewRow(hwndListView, 17, 40);
	ListView_SetItemText(hwndListView, 17, 1, L"e_res2[10]");
	ListView_SetItemText(hwndListView, 17, 2, L"保留字（20字节）");

	AddListViewRow(hwndListView, 18, 60);
	_stprintf_s(strBuffer, L"%08X", pDos->e_lfanew);
	ListView_SetItemText(hwndListView, 18, 1, strBuffer);
	ListView_SetItemText(hwndListView, 18, 2, L"新 exe 头文件地址");
}

//
//  函数: CLICK_IMAGE_NT_HEADERS64(PCHAR buffer)
//
//  目标: NT 头十六进制列表显示函数
//
VOID CLICK_IMAGE_NT_HEADERS64(PCHAR buffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	HextoList(buffer, pDos->e_lfanew, (pNt->FileHeader.SizeOfOptionalHeader + 24));
}

//
//  函数: CLICK_NT_Signature64(PCHAR buffer)
//
//  目标: NT 头签名列表显示函数
//
VOID CLICK_NT_Signature64(PCHAR buffer)
{
	WCHAR strBuffer[9];
	// 添加分列
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 250);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 200);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);

	AddListViewRow(hwndListView, 0, pDos->e_lfanew);
	_stprintf_s(strBuffer, L"%08X", pNt->Signature);
	ListView_SetItemText(hwndListView, 0, 1, strBuffer);
	ListView_SetItemText(hwndListView, 0, 2, L"NT 头签名");
	_stprintf_s(strBuffer, L"%c%c", WCHAR(pNt->Signature & 0xFF), WCHAR(pNt->Signature >> 8));
	ListView_SetItemText(hwndListView, 0, 3, strBuffer);
}

//
//  函数: CLICK_IMAGE_FILE_HEADER64(PCHAR buffer)
//
//  目标: 文件头列表显示函数
//
VOID CLICK_IMAGE_FILE_HEADER64(PCHAR buffer)
{
	WCHAR strBuffer[27];
	// 添加分列
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 170);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 280);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);

	AddListViewRow(hwndListView, 0, pDos->e_lfanew + 4);
	_stprintf_s(strBuffer, L"%04X", pNt->FileHeader.Machine);
	ListView_SetItemText(hwndListView, 0, 1, strBuffer);
	ListView_SetItemText(hwndListView, 0, 2, L"机器码");
	switch (pNt->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_IA64:
		wcscpy_s(strBuffer, L"Intel 64");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		wcscpy_s(strBuffer, L"AMD64 (K8)");
		break;
	case IMAGE_FILE_MACHINE_ARM64:
		wcscpy_s(strBuffer, L"ARM64 Little-Endian");
		break;
	default:
		wcscpy_s(strBuffer, L"");
		break;
	}
	ListView_SetItemText(hwndListView, 0, 3, strBuffer);

	AddListViewRow(hwndListView, 1, pDos->e_lfanew + 6);
	_stprintf_s(strBuffer, L"%04X", pNt->FileHeader.NumberOfSections);
	ListView_SetItemText(hwndListView, 1, 1, strBuffer);
	ListView_SetItemText(hwndListView, 1, 2, L"区块数");

	AddListViewRow(hwndListView, 2, pDos->e_lfanew + 8);
	_stprintf_s(strBuffer, L"%08X", pNt->FileHeader.TimeDateStamp);
	ListView_SetItemText(hwndListView, 2, 1, strBuffer);
	ListView_SetItemText(hwndListView, 2, 2, L"创建时间");
	time_t datatime = pNt->FileHeader.TimeDateStamp;
	_wctime_s(strBuffer, 26, &datatime);
	ListView_SetItemText(hwndListView, 2, 3, strBuffer);

	AddListViewRow(hwndListView, 3, pDos->e_lfanew + 12);
	_stprintf_s(strBuffer, L"%08X", pNt->FileHeader.PointerToSymbolTable);
	ListView_SetItemText(hwndListView, 3, 1, strBuffer);
	ListView_SetItemText(hwndListView, 3, 2, L"符号表指针");

	AddListViewRow(hwndListView, 4, pDos->e_lfanew + 16);
	_stprintf_s(strBuffer, L"%08X", pNt->FileHeader.NumberOfSymbols);
	ListView_SetItemText(hwndListView, 4, 1, strBuffer);
	ListView_SetItemText(hwndListView, 4, 2, L"符号表中的符号数");

	AddListViewRow(hwndListView,5, pDos->e_lfanew + 20);
	_stprintf_s(strBuffer, L"%04X", pNt->FileHeader.SizeOfOptionalHeader);
	ListView_SetItemText(hwndListView, 5, 1, strBuffer);
	ListView_SetItemText(hwndListView, 5, 2, L"Optional 头长度");

	AddListViewRow(hwndListView, 6, pDos->e_lfanew + 22);
	_stprintf_s(strBuffer, L"%04X", pNt->FileHeader.Characteristics);
	ListView_SetItemText(hwndListView, 6, 1, strBuffer);
	ListView_SetItemText(hwndListView, 6, 2, L"文件属性");
	DWORD line = 6;
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_RELOCS_STRIPPED, L"从文件中删除重定位信息");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_EXECUTABLE_IMAGE, L"文件是可执行的");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_LINE_NUMS_STRIPPED, L"从文件中删除的行号");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_LOCAL_SYMS_STRIPPED, L"从文件中剥离的本地符号");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_AGGRESIVE_WS_TRIM, L"积极修剪工作集");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_LARGE_ADDRESS_AWARE, L"应用可以处理 >2GB 地址");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_LO)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_BYTES_REVERSED_LO, L"机器字字节反转");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_32BIT_MACHINE, L"32 位字机");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_DEBUG_STRIPPED, L"从 .DBG 文件中剥离的调试信息");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, L"可在可移动媒体上复制并运行");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_NET_RUN_FROM_SWAP, L"可在网络上复制并运行");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_SYSTEM)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_SYSTEM, L"系统文件");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_DLL)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_DLL, L"DLL 文件");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_UP_SYSTEM_ONLY, L"文件只能在 UP 机器上运行");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_HI)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_BYTES_REVERSED_HI, L"机器字字节反转");
	}
}

//
//  函数: CLICK_IMAGE_OPTIONAL_HEADER64(PCHAR buffer)
//
//  目标: 文件头列表显示函数
//
VOID CLICK_IMAGE_OPTIONAL_HEADER64(PCHAR buffer)
{
	WCHAR strBuffer[27];
	// 添加分列
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 250);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 200);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);

	DWORD offsetAddr = pDos->e_lfanew + 24;	// 地址偏移增量基址
	DWORD line = 0;							// 行增量基数

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.Magic);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"标志位");
	ListView_SetItemText(hwndListView, line, 3, L"PE64/PE32+");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%02X", pNt->OptionalHeader.MajorLinkerVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"链接器主版本号");

	line += 1;
	offsetAddr += 1;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%02X", pNt->OptionalHeader.MinorLinkerVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"链接器次版本号");

	line += 1;
	offsetAddr += 1;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfCode);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"所有含有代码的区块大小");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfInitializedData);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"所有初始化数据区块大小");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfUninitializedData);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"所有未初始化数据区块大小");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.AddressOfEntryPoint);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"程序执行入口 RVA");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.BaseOfCode);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"代码区块起始 RVA");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	if (pNt->OptionalHeader.ImageBase > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pNt->OptionalHeader.ImageBase >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pNt->OptionalHeader.ImageBase);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.ImageBase);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"程序默认载入基地址");

	line += 1;
	offsetAddr += 8;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SectionAlignment);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"内存中区块的对齐值");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.FileAlignment);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"文件中区块的对齐值");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MajorOperatingSystemVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"操作系统主版本号");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MinorOperatingSystemVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"操作系统次版本号");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MajorImageVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"用户自定义主版本号");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MinorImageVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"用户自定义次版本号");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MajorSubsystemVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"所需子系统主版本号");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MinorSubsystemVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"所需子系统次版本号");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.Win32VersionValue);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Win32 版本值（保留，通常为0）");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfImage);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"映像载入内存后的总尺寸");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfHeaders);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"DOS 头、PE 头、区块表总大小");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.CheckSum);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"映像校验和");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.Subsystem);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"文件应用类型");
	switch (pNt->OptionalHeader.Subsystem)
	{
	case IMAGE_SUBSYSTEM_NATIVE:
		wcscpy_s(strBuffer, L"驱动程序或系统进程");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		wcscpy_s(strBuffer, L"图形化应用程序（GUI）");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		wcscpy_s(strBuffer, L"控制台应用程序（CUI）");
		break;
	default:
		wcscpy_s(strBuffer, L"未知应用程序类型");
		break;
	}
	ListView_SetItemText(hwndListView, line, 3, strBuffer);

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.DllCharacteristics);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"显示 DLL 特性的旗标");
	if (pNt->OptionalHeader.DllCharacteristics& IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, L"可以处理高熵 64 位虚拟地址空间");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, L"DLL 采用动态基地址");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, L"代码完整性检查");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_NX_COMPAT, L"与 NX 兼容");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, L"不独立运行");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_NO_SEH, L"不启用 SEH");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_NO_BIND, L"不绑定该文件");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_APPCONTAINER, L"应该在 AppContainer 中执行");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, L"驱动使用 WDM 模型");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_GUARD_CF, L"支持控制流保护");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, L"终端服务器感知");
	}

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	if (pNt->OptionalHeader.SizeOfStackReserve > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pNt->OptionalHeader.SizeOfStackReserve >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pNt->OptionalHeader.SizeOfStackReserve);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfStackReserve);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"初始化时栈的大小");

	line += 1;
	offsetAddr += 8;
	AddListViewRow(hwndListView, line, offsetAddr);
	if (pNt->OptionalHeader.SizeOfStackCommit > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pNt->OptionalHeader.SizeOfStackCommit >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pNt->OptionalHeader.SizeOfStackCommit);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfStackCommit);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"初始化时实际提交栈的大小");

	line += 1;
	offsetAddr += 8;
	AddListViewRow(hwndListView, line, offsetAddr);
	if (pNt->OptionalHeader.SizeOfHeapReserve > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pNt->OptionalHeader.SizeOfHeapReserve >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pNt->OptionalHeader.SizeOfHeapReserve);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfHeapReserve);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"初始化时保留堆的大小");

	line += 1;
	offsetAddr += 8;
	AddListViewRow(hwndListView, line, offsetAddr);
	if (pNt->OptionalHeader.SizeOfHeapCommit > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pNt->OptionalHeader.SizeOfHeapCommit >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pNt->OptionalHeader.SizeOfHeapCommit);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfHeapCommit);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"初始化时实际保留堆的大小");

	line += 1;
	offsetAddr += 8;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.LoaderFlags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"与调试相关，默认为0");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.NumberOfRvaAndSizes);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"数据目录表项数");

	WCHAR* DataDirName[0xF] = {			// 数据目录列表
		L"导出目录",
		L"导入目录",
		L"资源目录",
		L"异常目录",
		L"证书目录",
		L"基址重定位表",
		L"调试目录",
		L"架构特定数据",
		L"全局指针",
		L"TLS目录",
		L"加载配置目录",
		L"绑定导入目录",
		L"导入地址表（IAT）",
		L"延迟加载导入描述符",
		L"CLR 运行时描述符",
	};
	// 循环显示目录列表
	for (size_t i = 0; i < pNt->OptionalHeader.NumberOfRvaAndSizes-1; i++)
	{
		PIMAGE_DATA_DIRECTORY pDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory+i);

		// 第一行单独输出当前目录名
		line += 1;
		AddListViewRow(hwndListView, line, 0xFFFFFFFF);
		_stprintf_s(strBuffer, L"----%X----", i);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"-----------------------------");
		ListView_SetItemText(hwndListView, line, 3, L"----------------------");
		// 第二行输出虚拟地址
		if (i == 4)
		{
			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(strBuffer, L"%08X", pDir->VirtualAddress);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"文件偏移地址");
			ListView_SetItemText(hwndListView, line, 3, DataDirName[i]);
		}
		else
		{
			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(strBuffer, L"%08X", pDir->VirtualAddress);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"内存虚拟地址（RVA）");
			ListView_SetItemText(hwndListView, line, 3, DataDirName[i]);
		}
		// 第三行输出目录大小
		line += 1;
		offsetAddr += 4;
		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDir->Size);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"目录大小");
	}
	// 显示最后一个保留目录
	PIMAGE_DATA_DIRECTORY pDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + 15);
	line += 1;
	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	_stprintf_s(strBuffer, L"----%X----", 0xF);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"-----------------------------");
	ListView_SetItemText(hwndListView, line, 3, L"----------------------");
	
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDir->VirtualAddress);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"内存虚拟地址（RVA）");
	ListView_SetItemText(hwndListView, line, 3, L"保留目录");
	// 第三行输出目录大小
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDir->Size);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"目录大小");
}
	
//
//  函数: CLICK_IMAGE_SECTION_HEADERS64(PCHAR buffer)
//
//  目标: 区块十六进制列表显示函数
//
VOID CLICK_IMAGE_SECTION_HEADERS64(PCHAR buffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	DWORD offsetAddr = pDos->e_lfanew + 24 + pNt->FileHeader.SizeOfOptionalHeader;
	DWORD sectionLength = 40 * pNt->FileHeader.NumberOfSections;
	HextoList(buffer, offsetAddr, sectionLength);
}

//
//  函数: CLICK_IMAGE_EXPORT_DIRECTORY64(PCHAR buffer)
//
//  目标: 导出表列表显示函数
//
VOID CLICK_IMAGE_EXPORT_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 225);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 225);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pExportDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(RvaToOffset(pExportDir->VirtualAddress, buffer) + buffer);
	if (pExport->AddressOfFunctions == 0)
	{
		MessageBox(hwndListView, L"导出表为空", L"提示", MB_OK);
		return;
	}

	DWORD offsetAddr = RvaToOffset(pExportDir->VirtualAddress, buffer);	// 地址偏移增量基址
	DWORD line = 0;							// 行增量基数
	WCHAR strBuffer[9];

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->Characteristics);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"特征码");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->TimeDateStamp);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"时间日期");
	time_t datatime = pExport->TimeDateStamp;
	WCHAR timeBuffer[27];
	_wctime_s(timeBuffer, 26, &datatime);
	ListView_SetItemText(hwndListView, line, 3, timeBuffer);

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->MajorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"主版本号，一般为0");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->MinorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"次版本号，一般为0");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->Name);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"模块的真实名称 RVA");

	PCHAR szName = (PCHAR)(RvaToOffset(pExport->Name, buffer) + buffer);
	WCHAR strName[50];
	memset(strName, 0, sizeof(strName));
	MultiByteToWideChar(CP_ACP, 0, szName, strlen(szName) + 1, strName, sizeof(strName) / sizeof(strName[0]));
	ListView_SetItemText(hwndListView, line, 3, strName);

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->Base);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"基数");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->NumberOfFunctions);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"导出函数表个数");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->NumberOfNames);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"导出函数名个数");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->AddressOfFunctions);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"导出函数地址表 RVA");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->AddressOfNames);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"导出函数名称表 RVA");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->AddressOfNameOrdinals);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"序列号表 RVA");

	line += 1;
	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	_stprintf_s(strBuffer, L"%08X", 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"=====导出函数地址表=====");
	ListView_SetItemText(hwndListView, line, 3, L"=====导出函数名称表=====");

	PDWORD pEAT64 = (PDWORD)(RvaToOffset(pExport->AddressOfFunctions, buffer) + buffer);
	PDWORD pENT64 = (PDWORD)(RvaToOffset(pExport->AddressOfNames, buffer) + buffer);
	PWORD pID = (PWORD)(RvaToOffset(pExport->AddressOfNameOrdinals, buffer) + buffer);
	BOOL bFuncName = FALSE;
	for (size_t i = 0; i <= pExport->NumberOfFunctions; i++)
	{
		if (pEAT64[i] == 0)
		{
			continue;
		}

		line += 1;
		AddListViewRow(hwndListView, line, i + 1);

		for (size_t n = 0; n < pExport->NumberOfNames; n++)
		{
			if ((pID[n] + pExport->Base) == (i + 1))
			{
				_stprintf_s(strBuffer, L"%08X", pID[n]);
				ListView_SetItemText(hwndListView, line, 1, strBuffer);
				_stprintf_s(strBuffer, L"%08X", pEAT64[i]);
				ListView_SetItemText(hwndListView, line, 2, strBuffer);
				PCHAR szFuncName = (PCHAR)(RvaToOffset(pENT64[i], buffer) + buffer);
				memset(strName, 0, sizeof(strName));
				MultiByteToWideChar(CP_ACP, 0, szFuncName, strlen(szFuncName) + 1, strName, sizeof(strName) / sizeof(strName[0]));
				ListView_SetItemText(hwndListView, line, 3, strName);
				bFuncName = TRUE;
				break;
			}
		}
		if (!bFuncName)
		{
			_stprintf_s(strBuffer, L"%08X", pEAT64[i]);
			ListView_SetItemText(hwndListView, line, 2, strBuffer);
			wcscpy_s(strName, L"NULL");
			ListView_SetItemText(hwndListView, line, 3, strBuffer);
		}
	}
}

//
//  函数: CLICK_IMAGE_IMPORT_DIRECTORY64(PCHAR buffer)
//
//  目标: 导入目录列表显示函数
//
VOID CLICK_IMAGE_IMPORT_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 225);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 225);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pImportDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToOffset(pImportDir->VirtualAddress, buffer) + buffer);
	
	DWORD offsetAddr = RvaToOffset(pImportDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[9];

	while (pImport->Name != NULL)
	{
		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pImport->OriginalFirstThunk);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"导入名称表的 RVA");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pImport->TimeDateStamp);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"时间日期");
		time_t datatime = pImport->TimeDateStamp;
		WCHAR timeBuffer[27];
		_wctime_s(timeBuffer, 26, &datatime);
		ListView_SetItemText(hwndListView, line, 3, timeBuffer);
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pImport->ForwarderChain);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"API 多引用索引");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pImport->Name);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"DLL 名称指针地址 RVA");
		PCHAR szName = (PCHAR)(RvaToOffset(pImport->Name, buffer) + buffer);
		WCHAR strName[50];
		memset(strName, 0, sizeof(strName));
		MultiByteToWideChar(CP_ACP, 0, szName, strlen(szName) + 1, strName, sizeof(strName) / sizeof(strName[0]));
		ListView_SetItemText(hwndListView, line, 3, strName);
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pImport->FirstThunk);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"导入地址表的 RVA ");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, 0xFFFFFFFF);
		ListView_SetItemText(hwndListView, line, 1, L"--------");
		ListView_SetItemText(hwndListView, line, 2, L"------------------------");
		ListView_SetItemText(hwndListView, line, 3, L"------------------------");
		line += 1;

		pImport++;
	}
}

//
//  函数: CLICK_IMAGE_RESOURCE_DIRECTORY64(PCHAR buffer)
//
//  目标: 资源目录列表显示函数
//
VOID CLICK_IMAGE_RESOURCE_DIRECTORY64(PCHAR buffer)
{
	PWCHAR pResType[0x19] = {
		L"NULL",
		L"鼠标指针",
		L"位图",
		L"图标",
		L"菜单",
		L"对话框",
		L"字符串列表",
		L"字体目录",
		L"字体",
		L"快捷键",
		L"非格式化资源",
		L"消息列表",
		L"鼠标指针组",
		L"NULL",
		L"图标组",
		L"NULL",
		L"版本信息",
		L"DLGINCLUDE",
		L"NULL",
		L"PLUGPLAY",
		L"VXD",
		L"动态指针",
		L"动态图标",
		L"HTML",
		L"MANIFEST",
	};

	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 225);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 225);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pResourceDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_RESOURCE);
	PIMAGE_RESOURCE_DIRECTORY pResource = (PIMAGE_RESOURCE_DIRECTORY)(RvaToOffset(pResourceDir->VirtualAddress, buffer) + buffer);
	
	DWORD offsetAddr = RvaToOffset(pResourceDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[9];
	
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pResource->Characteristics);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"属性标志");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pResource->TimeDateStamp);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"时间日期");
	time_t datatime = pResource->TimeDateStamp;
	WCHAR timeBuffer[27];
	_wctime_s(timeBuffer, 26, &datatime);
	ListView_SetItemText(hwndListView, line, 3, timeBuffer);
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pResource->MajorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"主版本号");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pResource->MinorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"次版本号");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pResource->NumberOfNamedEntries);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"名称的资源条目个数");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pResource->NumberOfIdEntries);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ID 的资源条目个数");
	line += 1;
	offsetAddr += 2;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResource + 1);
	DWORD dwResEntryCount = pResource->NumberOfNamedEntries + pResource->NumberOfIdEntries;
	WCHAR strNameBuffer1[50];
	
	for (size_t i = 0; i < dwResEntryCount; i++)
	{
		wcscpy_s(strNameBuffer1, L"");
		if (pResEntry->NameIsString !=1)
		{
			if (pResEntry->Id < 0x19)
			{
				wcscpy_s(strNameBuffer1, pResType[pResEntry->Id]);
			}
			else
			{
				_stprintf_s(strNameBuffer1, L"%d", pResEntry->Id);
			}
		}
		else
		{
			PIMAGE_RESOURCE_DIR_STRING_U pResName = (PIMAGE_RESOURCE_DIR_STRING_U)(pResEntry->NameOffset + (DWORD)pResource);
			wchar_t* pEntryName = new wchar_t[pResName->Length + 1];
			memset(pEntryName, 0, sizeof(wchar_t)* (pResName->Length + 1));
			wcsncpy_s(pEntryName, pResName->Length + 1, pResName->NameString, pResName->Length);
			wcscpy_s(strNameBuffer1, pEntryName);
			delete[]pEntryName;
		}
		wcscat_s(strNameBuffer1, L" ");
		if (pResEntry->DataIsDirectory == 1)
		{
			PIMAGE_RESOURCE_DIRECTORY pSubRes = (PIMAGE_RESOURCE_DIRECTORY)(pResEntry->OffsetToDirectory + (DWORD)pResource);
			DWORD dwSubCount = pSubRes->NumberOfIdEntries + pSubRes->NumberOfNamedEntries;
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pSubResEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pSubRes + 1);
			WCHAR strIDBuffer[20];
			WCHAR strNameBuffer2[100];
			for (size_t n = 0; n < dwSubCount; n++)
			{
				wcscpy_s(strNameBuffer2, strNameBuffer1);
				if (pSubResEntry->NameIsString != 1)
				{
					_stprintf_s(strIDBuffer, L"%d", pSubResEntry->Id);
					wcscat_s(strNameBuffer2, strIDBuffer);
				}
				else
				{
					PIMAGE_RESOURCE_DIR_STRING_U pResName = (PIMAGE_RESOURCE_DIR_STRING_U)(pSubResEntry->NameOffset + (DWORD)pSubRes);
					wchar_t* pEntryName = new wchar_t[pResName->Length + 1];
					memset(pEntryName, 0, sizeof(wchar_t) * (pResName->Length + 1));
					wcsncpy_s(pEntryName, pResName->Length + 1, pResName->NameString, pResName->Length);
					wcscat_s(strNameBuffer2, pEntryName);
					delete[]pEntryName;
				}
				if (pSubResEntry->DataIsDirectory ==1)
				{
					PIMAGE_RESOURCE_DIRECTORY pDataRes = (PIMAGE_RESOURCE_DIRECTORY)(pSubResEntry->OffsetToDirectory + (DWORD)pResource);
					PIMAGE_RESOURCE_DIRECTORY_ENTRY pDataEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pDataRes + 1);
					if (pDataEntry->DataIsDirectory != 1)
					{
						PIMAGE_RESOURCE_DATA_ENTRY pData = (PIMAGE_RESOURCE_DATA_ENTRY)(pDataEntry->OffsetToData + (DWORD)pResource);
						offsetAddr = RvaToOffset(pResourceDir->VirtualAddress, buffer) + pDataEntry->OffsetToData;
						
						AddListViewRow(hwndListView, line, 0xFFFFFFFF);
						ListView_SetItemText(hwndListView, line, 1, L"----------");
						ListView_SetItemText(hwndListView, line, 2, L"--------------------------");
						ListView_SetItemText(hwndListView, line, 3, L"--------------------------");
						line += 1;

						AddListViewRow(hwndListView, line, offsetAddr);
						_stprintf_s(strBuffer, L"%08X", pData->OffsetToData);
						ListView_SetItemText(hwndListView, line, 1, strBuffer);
						ListView_SetItemText(hwndListView, line, 2, L"资源偏移地址 RVA");
						ListView_SetItemText(hwndListView, line, 3, strNameBuffer2);
						line += 1;
						offsetAddr += 4;

						AddListViewRow(hwndListView, line, offsetAddr);
						_stprintf_s(strBuffer, L"%08X", pData->Size);
						ListView_SetItemText(hwndListView, line, 1, strBuffer);
						ListView_SetItemText(hwndListView, line, 2, L"资源长度");
						line += 1;
						offsetAddr += 4;

						AddListViewRow(hwndListView, line, offsetAddr);
						_stprintf_s(strBuffer, L"%08X", pData->CodePage);
						ListView_SetItemText(hwndListView, line, 1, strBuffer);
						ListView_SetItemText(hwndListView, line, 2, L"代码页");
						line += 1;
						offsetAddr += 4;

						AddListViewRow(hwndListView, line, offsetAddr);
						_stprintf_s(strBuffer, L"%08X", pData->Reserved);
						ListView_SetItemText(hwndListView, line, 1, strBuffer);
						ListView_SetItemText(hwndListView, line, 2, L"保留字段");
						line += 1;
						offsetAddr += 4;
					}

				}
				pSubResEntry++;
			}
		}
		pResEntry++;
	}
}

//
//  函数: CLICK_IMAGE_EXCEPTION_DIRECTORY64(PCHAR buffer)
//
//  目标: 异常目录列表显示函数
//
VOID CLICK_IMAGE_EXCEPTION_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"开始地址[RVA]", 120);
	AddListViewColumn(hwndListView, 1, 2, L"结束地址[RVA]", 120);
	AddListViewColumn(hwndListView, 1, 3, L"unwind地址[RVA]", 150);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pExceptionDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION);
	PIMAGE_RUNTIME_FUNCTION_ENTRY pException = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(RvaToOffset(pExceptionDir->VirtualAddress, buffer) + buffer);
	
	DWORD offsetAddr = RvaToOffset(pExceptionDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[11];

	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, L"---Runtime---");
	ListView_SetItemText(hwndListView, line, 2, L"--Function--");
	ListView_SetItemText(hwndListView, line, 3, L"-----Table-----");
	line += 1;

	while (true)
	{
		if (pException->BeginAddress == 0)
		{
			break;
		}
		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"0x%08X", pException->BeginAddress);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		_stprintf_s(strBuffer, L"0x%08X", pException->EndAddress);
		ListView_SetItemText(hwndListView, line, 2, strBuffer);
		_stprintf_s(strBuffer, L"0x%08X", pException->UnwindInfoAddress);
		ListView_SetItemText(hwndListView, line, 3, strBuffer);
		line += 1;
		offsetAddr += 12;
		pException++;
	}
	
}

//
//  函数: CLICK_IMAGE_CERTIFICATE_DIRECTORY64(PCHAR buffer)
//
//  目标: 证书目录列表显示函数
//
VOID CLICK_IMAGE_CERTIFICATE_DIRECTORY64(PCHAR buffer)
{
	typedef struct _IMAGE_CERTIFICATE_TABLE {
		DWORD dwLength;
		WORD wRevision;
		WORD wType;
	}IMAGE_CERTIFICATE_TABLE, * PIMAGE_CERTIFICATE_TABLE;
	
	WCHAR strBuffer[32];
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 100);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 350);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pCertDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_SECURITY);
	PIMAGE_CERTIFICATE_TABLE pCertTable = (PIMAGE_CERTIFICATE_TABLE)(pCertDir->VirtualAddress + buffer);
	
	DWORD dwLength = pCertTable->dwLength;
	DWORD offsetAddr = pCertDir->VirtualAddress;
	DWORD line = 0;

	while (true)
	{
		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pCertTable->dwLength);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"证书块长度");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%04X", pCertTable->wRevision);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"证书版本");
		if (pCertTable->wRevision == 0x0100)
		{
			wcscpy_s(strBuffer, L"WIN_CERT_REVISION_1_0");
		}
		if (pCertTable->wRevision == 0x0200)
		{
			wcscpy_s(strBuffer, L"WIN_CERT_REVISION_2_0");
		}
		ListView_SetItemText(hwndListView, line, 3, strBuffer);
		line += 1;
		offsetAddr += 2;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%04X", pCertTable->wType);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"证书类型");
		if (pCertTable->wType == 0x0001)
		{
			wcscpy_s(strBuffer, L"WIN_CERT_TYPE_X509");
		}
		if (pCertTable->wType == 0x0002)
		{
			wcscpy_s(strBuffer, L"WIN_CERT_TYPE_PKCS_SIGNED_DATA");
		}
		if (pCertTable->wType == 0x0003)
		{
			wcscpy_s(strBuffer, L"WIN_CERT_TYPE_RESERVED_1");
		}
		if (pCertTable->wType == 0x0004)
		{
			wcscpy_s(strBuffer, L"WIN_CERT_TYPE_TS_STACK_SIGNED");
		}
		ListView_SetItemText(hwndListView, line, 3, strBuffer);
		line += 1;
		offsetAddr += 2;

		AddListViewRow(hwndListView, line, offsetAddr);
		offsetAddr = offsetAddr + pCertTable->dwLength - 8 -1;
		_stprintf_s(strBuffer, L"%08X", offsetAddr);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"证书内容");
		ListView_SetItemText(hwndListView, line, 3, L"pFile:内容起始地址，Data:内容结束地址");
		line++;
		offsetAddr++;

		if (dwLength == pCertDir->Size)
		{
			break;
		}

		pCertTable = (PIMAGE_CERTIFICATE_TABLE)(pCertTable + pCertTable->dwLength);
		dwLength += pCertTable->dwLength;
	}
}

//
//  函数: CLICK_IMAGE_BASE_RELOC_DIRECTORY64(PCHAR buffer)
//
//  目标: 重定位目录列表显示函数
//
VOID CLICK_IMAGE_BASE_RELOC_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 200);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 270);

	typedef struct _RELOCATIONDATA {
		WORD Offset : 12;
		WORD Type : 4;
	}RELOCATIONDATA, * PRELOCATIONDATA;

	WCHAR strSectionName[100];

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pRelocDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_BASERELOC);
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(RvaToOffset(pRelocDir->VirtualAddress, buffer) + buffer);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	DWORD offsetAddr = RvaToOffset(pRelocDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[15];
	WCHAR strTypeBuffer[50];
	WCHAR strOffsetBuffer[50];

	while (pReloc->SizeOfBlock != 0)
	{
		DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
		PRELOCATIONDATA pRelocData = (PRELOCATIONDATA)(pReloc + 1);

		for (size_t i = 0; i < pNt->FileHeader.NumberOfSections ; i++)
		{
			if (pReloc->VirtualAddress >= pSection[i].VirtualAddress && pReloc->VirtualAddress <= (pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize))
			{
				// 将 PBYTE 转化为 LPWSTR
				memset(strSectionName, 0, sizeof(strSectionName));
				MultiByteToWideChar(CP_ACP, 0, (PCHAR)pSection[i].Name, strlen((PCHAR)pSection[i].Name) + 1, strSectionName, sizeof(strSectionName) / sizeof(strSectionName[0]));
			}
		}
		AddListViewRow(hwndListView, line, 0xFFFFFFFF);
		ListView_SetItemText(hwndListView, line, 1, L"-------");
		ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
		ListView_SetItemText(hwndListView, line, 3, L"------------------------------");
		line += 1;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pReloc->VirtualAddress);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"区块重定位地址 RVA");
		ListView_SetItemText(hwndListView, line, 3, strSectionName);
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pReloc->SizeOfBlock);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"当前重定位块大小");
		_stprintf_s(strBuffer, L"当前块项数：%X", dwCount);
		ListView_SetItemText(hwndListView, line, 3, strBuffer);
		line += 1;
		offsetAddr += 4;

		for (size_t n = 0; n < dwCount; n++)
		{
			wcscpy_s(strTypeBuffer, L"");
			switch (pRelocData[n].Type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_ABSOLUTE");
				break;
			case IMAGE_REL_BASED_HIGH:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_HIGH");
				break;
			case IMAGE_REL_BASED_LOW:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_LOW");
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_HIGHLOW");
				break;
			case IMAGE_REL_BASED_HIGHADJ:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_HIGHADJ");
				break;
			case IMAGE_REL_BASED_MACHINE_SPECIFIC_5:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_MACHINE_SPECIFIC_5");
				break;
			case IMAGE_REL_BASED_RESERVED:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_RESERVED");
				break;
			case IMAGE_REL_BASED_MACHINE_SPECIFIC_7:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_MACHINE_SPECIFIC_7");
				break;
			case IMAGE_REL_BASED_MACHINE_SPECIFIC_8:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_MACHINE_SPECIFIC_8");
				break;
			case IMAGE_REL_BASED_MACHINE_SPECIFIC_9:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_MACHINE_SPECIFIC_9");
				break;
			case IMAGE_REL_BASED_DIR64:
				wcscpy_s(strTypeBuffer, L"IMAGE_REL_BASED_DIR64");
				break;
			default:
				break;
			}
			
			DWORD dwRVA = pRelocData[n].Offset + pReloc->VirtualAddress;
			DWORD dwOffset = RvaToOffset(dwRVA, buffer);

			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(strBuffer, L"%04X", pRelocData[n]);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			ListView_SetItemText(hwndListView, line, 2, strTypeBuffer);
			_stprintf_s(strOffsetBuffer, L"RVA:%08X Offset:%08X", dwRVA, dwOffset);
			ListView_SetItemText(hwndListView, line, 3, strOffsetBuffer);
			line += 1;
			offsetAddr += 2;
		}

		pReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pReloc + pReloc->SizeOfBlock);
	}
}

//
//  函数: CLICK_IMAGE_DEBUG_DIRECTORY64(PCHAR buffer)
//
//  目标: 调试目录列表显示函数
//
VOID CLICK_IMAGE_DEBUG_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 200);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 250);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pDebugDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_DEBUG);
	PIMAGE_DEBUG_DIRECTORY pDebug = (PIMAGE_DEBUG_DIRECTORY)(RvaToOffset(pDebugDir->VirtualAddress, buffer) + buffer);
	
	DWORD offsetAddr = RvaToOffset(pDebugDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[40];

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDebug->Characteristics);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"未使用");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDebug->TimeDateStamp);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"时间日期");
	time_t datatime = pDebug->TimeDateStamp;
	WCHAR timeBuffer[27];
	_wctime_s(timeBuffer, 26, &datatime);
	ListView_SetItemText(hwndListView, line, 3, timeBuffer);
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pDebug->MajorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"主版本");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pDebug->MinorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"次版本");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDebug->Type);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"调试信息类型");
	switch (pDebug->Type)
	{
	case IMAGE_DEBUG_TYPE_UNKNOWN:
		wcscpy_s(strBuffer, L"所有工具都忽略的未知值");
		break;
	case IMAGE_DEBUG_TYPE_COFF:
		wcscpy_s(strBuffer, L"COFF 调试信息");
		break;
	case IMAGE_DEBUG_TYPE_CODEVIEW:
		wcscpy_s(strBuffer, L"Visual C++ 调试信息");
		break;
	case IMAGE_DEBUG_TYPE_FPO:
		wcscpy_s(strBuffer, L"帧指针省略 (FPO) 信息");
		break;
	case IMAGE_DEBUG_TYPE_MISC:
		wcscpy_s(strBuffer, L"DBG 文件的位置");
		break;
	case IMAGE_DEBUG_TYPE_EXCEPTION:
		wcscpy_s(strBuffer, L".pdata 部分的副本");
		break;
	case IMAGE_DEBUG_TYPE_FIXUP:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_FIXUP");
		break;
	case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_OMAP_TO_SRC");
		break;
	case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_OMAP_FROM_SRC");
		break;
	case IMAGE_DEBUG_TYPE_BORLAND:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_BORLAND");
		break;
	case IMAGE_DEBUG_TYPE_RESERVED10:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_RESERVED10");
		break;
	case IMAGE_DEBUG_TYPE_CLSID:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_CLSID");
		break;
	case IMAGE_DEBUG_TYPE_VC_FEATURE:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_VC_FEATURE");
		break;
	case IMAGE_DEBUG_TYPE_POGO:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_POGO");
		break;
	case IMAGE_DEBUG_TYPE_ILTCG:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_ILTCG");
		break;
	case IMAGE_DEBUG_TYPE_MPX:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_MPX");
		break;
	case IMAGE_DEBUG_TYPE_REPRO:
		wcscpy_s(strBuffer, L"PE 确定性或再现性");
		break;
	case IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:
		wcscpy_s(strBuffer, L"IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS");
		break;
	default:
		break;
	}
	ListView_SetItemText(hwndListView, line, 3, strBuffer);
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDebug->SizeOfData);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"调试数据大小");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDebug->AddressOfRawData);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"调试数据的内存地址 RVA");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDebug->AddressOfRawData);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"调试数据的文件偏移地址");
	line += 1;
	offsetAddr += 4;
}

//
//  函数: CLICK_IMAGE_TLS_DIRECTORY64(PCHAR buffer)
//
//  目标: TLS目录列表显示函数
//
VOID CLICK_IMAGE_TLS_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 200);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 250);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pTLSDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_TLS);
	PIMAGE_TLS_DIRECTORY64 pTLS = (PIMAGE_TLS_DIRECTORY64)(RvaToOffset(pTLSDir->VirtualAddress, buffer) + buffer);

	DWORD offsetAddr = RvaToOffset(pTLSDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[17];

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pTLS->StartAddressOfRawData > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pTLS->StartAddressOfRawData>>32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pTLS->StartAddressOfRawData);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pTLS->StartAddressOfRawData);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"起始地址");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pTLS->EndAddressOfRawData > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pTLS->EndAddressOfRawData >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pTLS->EndAddressOfRawData);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pTLS->EndAddressOfRawData);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"结束地址");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pTLS->AddressOfIndex > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pTLS->AddressOfIndex >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pTLS->AddressOfIndex);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pTLS->AddressOfIndex);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"索引地址");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pTLS->AddressOfCallBacks > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pTLS->AddressOfCallBacks >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pTLS->AddressOfCallBacks);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pTLS->AddressOfCallBacks);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"回调地址");
	ListView_SetItemText(hwndListView, line, 3, L"PIMAGE_TLS_CALLBACK 结构");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pTLS->SizeOfZeroFill);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"零填充大小");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pTLS->Characteristics);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"特征");
	line += 1;
	offsetAddr += 4;
}

//
//  函数: CLICK_IMAGE_LOAD_CONFIG_DIRECTORY64(PCHAR buffer)
//
//  目标: 加载配置目录列表显示函数
//
VOID CLICK_IMAGE_LOAD_CONFIG_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 220);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 230);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pLoadConfigDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	PIMAGE_LOAD_CONFIG_DIRECTORY64 pLoadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY64)(RvaToOffset(pLoadConfigDir->VirtualAddress, buffer) + buffer);

	DWORD offsetAddr = RvaToOffset(pLoadConfigDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[17];

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->Size);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"结构的大小");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->TimeDateStamp);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"时间日期");
	time_t datatime = pLoadConfig->TimeDateStamp;
	WCHAR timeBuffer[27];
	_wctime_s(timeBuffer, 26, &datatime);
	ListView_SetItemText(hwndListView, line, 3, timeBuffer);
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->MajorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"主要版本号");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->MinorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"次要版本号");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->GlobalFlagsClear);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"全局标志清除");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->GlobalFlagsSet);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"全局标志集合");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->CriticalSectionDefaultTimeout);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"临界区默认超时值");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->DeCommitFreeBlockThreshold > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->DeCommitFreeBlockThreshold >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->DeCommitFreeBlockThreshold);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->DeCommitFreeBlockThreshold);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"DeCommitFreeBlockThreshold");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->DeCommitTotalFreeThreshold > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->DeCommitTotalFreeThreshold >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->DeCommitTotalFreeThreshold);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->DeCommitTotalFreeThreshold);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"DeCommitTotalFreeThreshold");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->LockPrefixTable > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->LockPrefixTable >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->LockPrefixTable);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->LockPrefixTable);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"锁定前缀表");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->MaximumAllocationSize > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->MaximumAllocationSize >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->MaximumAllocationSize);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->MaximumAllocationSize);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"最大分配大小");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->VirtualMemoryThreshold > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->VirtualMemoryThreshold >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->VirtualMemoryThreshold);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->VirtualMemoryThreshold);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"堆栈内存阈值");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->ProcessAffinityMask > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->ProcessAffinityMask >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->ProcessAffinityMask);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->ProcessAffinityMask);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"进程关联掩码");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->ProcessHeapFlags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"进程堆标志");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->CSDVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"服务包版本");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->DependentLoadFlags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"相关加载标志");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->EditList > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->EditList >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->EditList);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->EditList);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"编辑列表");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->SecurityCookie > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->SecurityCookie >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->SecurityCookie);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->SecurityCookie);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Cookie 指针");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->SEHandlerTable > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->SEHandlerTable >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->SEHandlerTable);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->SEHandlerTable);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"SE 处理程序表");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->SEHandlerCount > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->SEHandlerCount >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->SEHandlerCount);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->SEHandlerCount);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"SE 处理程序表计数");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardCFCheckFunctionPointer > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardCFCheckFunctionPointer >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardCFCheckFunctionPointer);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardCFCheckFunctionPointer);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"存储控制流保护检查函数指针");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardCFDispatchFunctionPointer > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardCFDispatchFunctionPointer >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardCFDispatchFunctionPointer);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardCFDispatchFunctionPointer);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"存储控制流保护调度函数指针");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardCFFunctionTable > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardCFFunctionTable >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardCFFunctionTable);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardCFFunctionTable);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"控制流保护函数表");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardCFFunctionCount > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardCFFunctionCount >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardCFFunctionCount);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardCFFunctionCount);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"控制流保护函数计数");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardFlags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"控制流保护相关标志");
	line += 1;
	offsetAddr += 4;

	PIMAGE_LOAD_CONFIG_CODE_INTEGRITY pCI = (PIMAGE_LOAD_CONFIG_CODE_INTEGRITY)(offsetAddr + buffer);
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pCI->Flags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"标志位");
	ListView_SetItemText(hwndListView, line, 3, L"Flags PIMAGE_LOAD_CONFIG_CODE_INTEGRITY");
	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pCI->Catalog);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"目录属性");
	ListView_SetItemText(hwndListView, line, 3, L"Catalog PIMAGE_LOAD_CONFIG_CODE_INTEGRITY");
	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pCI->CatalogOffset);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"目录偏移");
	ListView_SetItemText(hwndListView, line, 3, L"CatalogOffset PIMAGE_LOAD_CONFIG_CODE_INTEGRITY");
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pCI->Reserved);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"保留项");
	ListView_SetItemText(hwndListView, line, 3, L"Reserved PIMAGE_LOAD_CONFIG_CODE_INTEGRITY");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardAddressTakenIatEntryTable > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardAddressTakenIatEntryTable >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardAddressTakenIatEntryTable);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardAddressTakenIatEntryTable);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"存储控制流保护地址取IAT表");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardAddressTakenIatEntryCount > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardAddressTakenIatEntryCount >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardAddressTakenIatEntryCount);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardAddressTakenIatEntryCount);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"存储控制流保护地址取IAT表计数");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardLongJumpTargetTable > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardLongJumpTargetTable >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardLongJumpTargetTable);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardLongJumpTargetTable);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"控制流保护长跳转目标表");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardLongJumpTargetCount > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardLongJumpTargetCount >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardLongJumpTargetCount);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardLongJumpTargetCount);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"控制流保护长跳转目标表计数");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->DynamicValueRelocTable > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->DynamicValueRelocTable >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->DynamicValueRelocTable);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->DynamicValueRelocTable);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"动态重定位表");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->CHPEMetadataPointer > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->CHPEMetadataPointer >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->CHPEMetadataPointer);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->CHPEMetadataPointer);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"CHPE元数据指针");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardRFFailureRoutine > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardRFFailureRoutine >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardRFFailureRoutine);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardRFFailureRoutine);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"回流保护故障例程");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardRFFailureRoutineFunctionPointer > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardRFFailureRoutineFunctionPointer >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardRFFailureRoutineFunctionPointer);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardRFFailureRoutineFunctionPointer);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"回流保护故障例程计数");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->DynamicValueRelocTableOffset);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"动态重定位表偏移");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->DynamicValueRelocTableSection);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"动态重定位表块");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->Reserved2);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"保留项");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardRFVerifyStackPointerFunctionPointer > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardRFVerifyStackPointerFunctionPointer >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardRFVerifyStackPointerFunctionPointer);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardRFVerifyStackPointerFunctionPointer);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"回流保护验证堆栈指针函数指针");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->HotPatchTableOffset);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"热补丁表偏移");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->Reserved3);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"保留项");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->EnclaveConfigurationPointer > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->EnclaveConfigurationPointer >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->EnclaveConfigurationPointer);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->EnclaveConfigurationPointer);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Enclave 配置指针");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->VolatileMetadataPointer > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->VolatileMetadataPointer >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->VolatileMetadataPointer);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->VolatileMetadataPointer);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"易失性元数据指针");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardEHContinuationTable > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardEHContinuationTable >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardEHContinuationTable);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardEHContinuationTable);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"EH 延续表");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	if (pLoadConfig->GuardEHContinuationCount > 0x100000000)
	{
		WCHAR tempBuffer[9];
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardEHContinuationCount >> 32);
		wcscpy_s(strBuffer, tempBuffer);
		_stprintf_s(tempBuffer, L"%X", pLoadConfig->GuardEHContinuationCount);
		wcscat_s(strBuffer, tempBuffer);
	}
	else
	{
		_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardEHContinuationCount);
	}
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"EH 延续表计数");
	line += 1;
	offsetAddr += 8;
}

//
//  函数: CLICK_IMAGE_BOUND_IMPORT_DIRECTORY64(PCHAR buffer)
//
//  目标: 绑定导入目录列表显示函数
//
VOID CLICK_IMAGE_BOUND_IMPORT_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 200);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 250);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pBoundDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBound = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(RvaToOffset(pBoundDir->VirtualAddress, buffer) + buffer);

	DWORD dwOffset = RvaToOffset(pBoundDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[9];
	DWORD offsetAddr = dwOffset;
	while (true)
	{
		AddListViewRow(hwndListView, line, 0xFFFFFFFF);
		ListView_SetItemText(hwndListView, line, 1, L"----------");
		ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
		ListView_SetItemText(hwndListView, line, 3, L"-----------------------------");
		line+=1;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pBound->TimeDateStamp);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"时间日期");
		time_t datatime = pBound->TimeDateStamp;
		WCHAR timeBuffer[27];
		_wctime_s(timeBuffer, 26, &datatime);
		ListView_SetItemText(hwndListView, line, 3, timeBuffer);
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%04X", pBound->OffsetModuleName);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"模块名称");
		PCHAR szName = (PCHAR)(pBound->OffsetModuleName + dwOffset + buffer);
		WCHAR strNameBuffer[50];
		memset(strNameBuffer, 0, sizeof(strNameBuffer));
		MultiByteToWideChar(CP_ACP, 0, szName, strlen(szName) + 1, strNameBuffer, sizeof(strNameBuffer) / sizeof(strNameBuffer[0]));
		ListView_SetItemText(hwndListView, line, 3, strNameBuffer);
		line += 1;
		offsetAddr += 2;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%04X", pBound->OffsetModuleName);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"REF 个数");
		line += 1;
		offsetAddr += 2;

		PIMAGE_BOUND_FORWARDER_REF pREF = PIMAGE_BOUND_FORWARDER_REF(offsetAddr + buffer);
		for (size_t i = 0; i < pBound->NumberOfModuleForwarderRefs; i++)
		{
			AddListViewRow(hwndListView, line, 0);
			_stprintf_s(strBuffer, L"%X", i);
			ListView_SetItemText(hwndListView, line, 2, strBuffer);
			ListView_SetItemText(hwndListView, line, 3, L"IMAGE_BOUND_FORWARDER_REF");
			line += 1;

			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(strBuffer, L"%08X", pREF->TimeDateStamp);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"时间日期");
			datatime = pREF->TimeDateStamp;
			_wctime_s(timeBuffer, 26, &datatime);
			ListView_SetItemText(hwndListView, line, 3, timeBuffer);
			line += 1;
			offsetAddr += 4;

			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(strBuffer, L"%04X", pREF->OffsetModuleName);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"模块名称");
			szName = (PCHAR)(pREF->OffsetModuleName + dwOffset + buffer);
			memset(strNameBuffer, 0, sizeof(strNameBuffer));
			MultiByteToWideChar(CP_ACP, 0, szName, strlen(szName) + 1, strNameBuffer, sizeof(strNameBuffer) / sizeof(strNameBuffer[0]));
			ListView_SetItemText(hwndListView, line, 3, strNameBuffer);
			line += 1;
			offsetAddr += 2;

			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(strBuffer, L"%04X", pREF->Reserved);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"保留项");
			line += 1;
			offsetAddr += 2;

			pREF = PIMAGE_BOUND_FORWARDER_REF(pREF + 1);
		}
		

		pBound = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(offsetAddr + buffer);
		if (pBound->TimeDateStamp == 0)
		{
			break;
		}
	}	
}

//
//  函数: CLICK_IMAGE_IAT_DIRECTORY64(PCHAR buffer)
//
//  目标: 导入地址表列表显示函数
//
VOID CLICK_IMAGE_IAT_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Address", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Hint", 50);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 400);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pImportDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToOffset(pImportDir->VirtualAddress, buffer) + buffer);

	DWORD offsetAddr = RvaToOffset(pImportDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[9];
	WCHAR strName[70];

	while (pImport->Name != NULL)
	{
		PCHAR szName = (PCHAR)(RvaToOffset(pImport->Name, buffer) + buffer);
		WCHAR strDllName[50];
		memset(strDllName, 0, sizeof(strDllName));
		MultiByteToWideChar(CP_ACP, 0, szName, strlen(szName) + 1, strDllName, sizeof(strDllName) / sizeof(strDllName[0]));

		AddListViewRow(hwndListView, line, 0xFFFFFFFF);
		ListView_SetItemText(hwndListView, line, 1, L"----------");
		ListView_SetItemText(hwndListView, line, 2, L"----");
		wcscat_s(strDllName, L"------------------------------");
		ListView_SetItemText(hwndListView, line, 3, strDllName);
		line += 1;


		PIMAGE_THUNK_DATA64 pIAT = (PIMAGE_THUNK_DATA64)(RvaToOffset(pImport->OriginalFirstThunk, buffer) + buffer);
		offsetAddr = RvaToOffset(pImport->FirstThunk, buffer);
		DWORD index = 0;

		while (pIAT->u1.Ordinal != 0)
		{
			AddListViewRow(hwndListView, line, offsetAddr + index);
			_stprintf_s(strBuffer, L"%08X", pIAT->u1.Function);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			if (!((pIAT->u1.Ordinal >> 32) & 0x80000000))
			{
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(RvaToOffset(pIAT->u1.AddressOfData, buffer) + buffer);
				_stprintf_s(strBuffer, L"%04X", pName->Hint);
				ListView_SetItemText(hwndListView, line, 2, strBuffer);
				szName = pName->Name;
				memset(strName, 0, sizeof(strName));
				MultiByteToWideChar(CP_ACP, 0, szName, strlen(szName) + 1, strName, sizeof(strName) / sizeof(strName[0]));
				ListView_SetItemText(hwndListView, line, 3, strName);
			}
			else
			{
				wcscpy_s(strBuffer, L"----");
				wcscpy_s(strName, L"Memory Address:");
				WCHAR tempBuffer[9];
				_stprintf_s(tempBuffer, L"%08X", pIAT->u1.Ordinal >> 32);
				wcscat_s(strName, tempBuffer);
				_stprintf_s(tempBuffer, L"%08X", pIAT->u1.Ordinal);
				wcscat_s(strName, tempBuffer);
			}
			ListView_SetItemText(hwndListView, line, 2, strBuffer);
			ListView_SetItemText(hwndListView, line, 3, strName);
			line += 1;
			index += 8;

			pIAT++;
		}
		pImport++;
	}
}

//
//  函数: CLICK_IMAGE_DELAY_IMPORT_DIRECTORY64(PCHAR buffer, LPWSTR szText)
//
//  目标: 延迟加载导入目录列表显示函数
//
VOID CLICK_IMAGE_DELAY_IMPORT_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 200);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 250);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pDelayImportDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayImport = (PIMAGE_DELAYLOAD_DESCRIPTOR)(RvaToOffset(pDelayImportDir->VirtualAddress, buffer) + buffer);

	DWORD offsetAddr = RvaToOffset(pDelayImportDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[9];
	PCHAR szName;
	WCHAR strNameBuffer[50];
	time_t datatime;
	WCHAR timeBuffer[27];
	while (pDelayImport->DllNameRVA != 0)
	{
		AddListViewRow(hwndListView, line, 0xFFFFFFFF);
		ListView_SetItemText(hwndListView, line, 1, L"----------");
		ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
		ListView_SetItemText(hwndListView, line, 3, L"-----------------------------");
		line += 1;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->Attributes);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"属性");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->DllNameRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"模块名称");
		szName = (PCHAR)(RvaToOffset(pDelayImport->DllNameRVA, buffer) + buffer);
		memset(strNameBuffer, 0, sizeof(strNameBuffer));
		MultiByteToWideChar(CP_ACP, 0, szName, strlen(szName) + 1, strNameBuffer, sizeof(strNameBuffer) / sizeof(strNameBuffer[0]));
		ListView_SetItemText(hwndListView, line, 3, strNameBuffer);
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->ModuleHandleRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"模块句柄");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->ImportAddressTableRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"延迟导入地址表");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->ImportNameTableRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"延迟导入名称表");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->BoundImportAddressTableRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"绑定延迟导入表");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->UnloadInformationTableRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"卸载延迟导入表");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->TimeDateStamp);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"时间日期");
		datatime = pDelayImport->TimeDateStamp;
		_wctime_s(timeBuffer, 26, &datatime);
		ListView_SetItemText(hwndListView, line, 3, timeBuffer);
		line += 1;
		offsetAddr += 4;

		pDelayImport++;
	}

	
}

//
//  函数: CLICK_IMAGE_COM_DESCRIPTOR_DIRECTORY64(PCHAR buffer, LPWSTR szText)
//
//  目标: COM 运行目录列表显示函数
//
VOID CLICK_IMAGE_COM_DESCRIPTOR_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 200);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 250);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pCOMDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	PIMAGE_COR20_HEADER pCOM = (PIMAGE_COR20_HEADER)(RvaToOffset(pCOMDir->VirtualAddress, buffer) + buffer);

	DWORD offsetAddr = RvaToOffset(pCOMDir->VirtualAddress, buffer);
	DWORD line = 0;
	WCHAR strBuffer[9];

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pCOM->cb);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"cb");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pCOM->MajorRuntimeVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"MajorRuntimeVersion");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pCOM->MinorRuntimeVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"MinorRuntimeVersion");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, L"----------");
	ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
	ListView_SetItemText(hwndListView, line, 3, L"-----------------------------");
	line += 1;

	PIMAGE_DATA_DIRECTORY pMetaData = (PIMAGE_DATA_DIRECTORY)(offsetAddr + buffer);
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pMetaData->VirtualAddress);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"VirtualAddress");
	ListView_SetItemText(hwndListView, line, 3, L"MetaData");
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pMetaData->Size);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Size");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, L"----------");
	ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
	ListView_SetItemText(hwndListView, line, 3, L"-----------------------------");
	line += 1;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pCOM->Flags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Flags");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pCOM->EntryPointToken);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"EntryPoint Token/RVA");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, L"----------");
	ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
	ListView_SetItemText(hwndListView, line, 3, L"-----------------------------");
	line += 1;

	PIMAGE_DATA_DIRECTORY pResources = (PIMAGE_DATA_DIRECTORY)(offsetAddr + buffer);
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pResources->VirtualAddress);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"VirtualAddress");
	ListView_SetItemText(hwndListView, line, 3, L"Resources");
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pResources->Size);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Size");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, L"----------");
	ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
	ListView_SetItemText(hwndListView, line, 3, L"-----------------------------");
	line += 1;

	PIMAGE_DATA_DIRECTORY pStrongNameSignature = (PIMAGE_DATA_DIRECTORY)(offsetAddr + buffer);
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pStrongNameSignature->VirtualAddress);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"VirtualAddress");
	ListView_SetItemText(hwndListView, line, 3, L"StrongNameSignature");
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pStrongNameSignature->Size);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Size");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, L"----------");
	ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
	ListView_SetItemText(hwndListView, line, 3, L"-----------------------------");
	line += 1;

	PIMAGE_DATA_DIRECTORY pCodeManagerTable = (PIMAGE_DATA_DIRECTORY)(offsetAddr + buffer);
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pCodeManagerTable->VirtualAddress);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"VirtualAddress");
	ListView_SetItemText(hwndListView, line, 3, L"CodeManagerTable");
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pCodeManagerTable->Size);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Size");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, L"----------");
	ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
	ListView_SetItemText(hwndListView, line, 3, L"-----------------------------");
	line += 1;

	PIMAGE_DATA_DIRECTORY pVTableFixups = (PIMAGE_DATA_DIRECTORY)(offsetAddr + buffer);
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pVTableFixups->VirtualAddress);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"VirtualAddress");
	ListView_SetItemText(hwndListView, line, 3, L"VTableFixups");
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pVTableFixups->Size);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Size");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, L"----------");
	ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
	ListView_SetItemText(hwndListView, line, 3, L"-----------------------------");
	line += 1;

	PIMAGE_DATA_DIRECTORY pExportAddressTableJumps = (PIMAGE_DATA_DIRECTORY)(offsetAddr + buffer);
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExportAddressTableJumps->VirtualAddress);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"VirtualAddress");
	ListView_SetItemText(hwndListView, line, 3, L"ExportAddressTableJumps");
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExportAddressTableJumps->Size);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Size");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, L"----------");
	ListView_SetItemText(hwndListView, line, 2, L"-----------------------");
	ListView_SetItemText(hwndListView, line, 3, L"-----------------------------");
	line += 1;

	PIMAGE_DATA_DIRECTORY pManagedNativeHeader = (PIMAGE_DATA_DIRECTORY)(offsetAddr + buffer);
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pManagedNativeHeader->VirtualAddress);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"VirtualAddress");
	ListView_SetItemText(hwndListView, line, 3, L"ManagedNativeHeader");
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pManagedNativeHeader->Size);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Size");
	line += 1;
	offsetAddr += 4;
}

//
//  函数: CLICK_SECTION_LIST64(PCHAR buffer, LPWSTR szText)
//
//  目标: 区块项点击列表显示函数
//
VOID CLICK_SECTION_LIST64(PCHAR buffer, LPWSTR szText)
{
	WCHAR strSectionName[50];
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	
	for (size_t i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		WCHAR strBuffer[50] = L"SECTION";
		// 将 PBYTE 转化为 LPWSTR
		memset(strSectionName, 0, sizeof(strSectionName));
		MultiByteToWideChar(CP_ACP, 0, (PCHAR)pSection[i].Name, strlen((PCHAR)pSection[i].Name) + 1, strSectionName, sizeof(strSectionName) / sizeof(strSectionName[0]));
		wcscat_s(strBuffer, strSectionName);
		if (!wcscmp(szText, strSectionName))			// 点击 SECTION 头内节区列表，显示输出
		{
			// 添加分列
			AddListViewColumn(hwndListView, 1, 0, L"pFile", 75);
			AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
			AddListViewColumn(hwndListView, 0, 2, L"Description", 270);
			AddListViewColumn(hwndListView, 0, 3, L"Value", 180);

			WCHAR dataBuffer[9];

			// 地址偏移增量基址
			DWORD offsetAddr = pDos->e_lfanew + 24 + pNt->FileHeader.SizeOfOptionalHeader + (i * 40);
			DWORD line = 0;		// 行增量基数

			AddListViewRow(hwndListView, line, offsetAddr);
			ListView_SetItemText(hwndListView, line, 2, L"区块名");
			ListView_SetItemText(hwndListView, line, 3, strSectionName);

			line += 1;
			offsetAddr += 8;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].Misc.VirtualSize);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"内存中的大小");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].VirtualAddress);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"区块的起始地址 RVA");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].SizeOfRawData);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"磁盘文件中节区所占大小");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].PointerToRawData);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"磁盘文件中节区起始位置");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].PointerToRelocations);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"在 OBJ 文件中使用，重定位的偏移");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].PointerToLinenumbers);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"行号表的偏移（调试用）");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%04X", pSection[i].NumberOfRelocations);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"在 OBJ 文件中使用，重定位项数量");

			line += 1;
			offsetAddr += 2;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%04X", pSection[i].NumberOfLinenumbers);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"行号表中行号的数量");

			line += 1;
			offsetAddr += 2;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].Characteristics);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"区块的属性");
			if (pSection[i].Characteristics & IMAGE_SCN_CNT_CODE)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_CNT_CODE, L"区块包含代码");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_CNT_INITIALIZED_DATA, L"区块包含初始化数据");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_CNT_UNINITIALIZED_DATA, L"区块包含未初始化数据");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_LNK_INFO)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_LNK_INFO, L"区块包含注释或其它类型的信息");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_LNK_REMOVE)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_LNK_REMOVE, L"区块内容不会成为镜像的一部分");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_LNK_COMDAT)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_LNK_COMDAT, L"区块包含 comdat");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_NO_DEFER_SPEC_EXC, L"重置此区块 TLB 条目中的推测性异常处理位");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_GPREL)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_GPREL, L"区块内容可被GP访问");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_LNK_NRELOC_OVFL, L"区块包含扩展重定位");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_DISCARDABLE, L"区块可被丢弃");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_NOT_CACHED, L"区块不可缓存");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_NOT_PAGED)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_NOT_PAGED, L"区块不可分页");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_SHARED)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_SHARED, L"区块可共享");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_EXECUTE, L"区块可执行");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_READ)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_READ, L"区块可读");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_WRITE, L"区块可写");
			}

			break;
		}
		if (!wcscmp(szText, strBuffer))				// 点击根目录下 SECTION 节区项，显示输出
		{
			HextoList(buffer, pSection[i].PointerToRawData, pSection[i].SizeOfRawData);
			break;
		}
	}
}

//
//  函数: TreeToList64(PCHAR buffer, LPWSTR szText, LPWSTR lpFilePath)
//
//  目标: 树视图子节点列表视图响应
//
VOID TreeToList64(PCHAR buffer, LPWSTR szText, LPWSTR lpFilePath)
{
	if (!wcscmp(szText, lpFilePath))                            // 点击文件名响应
	{
		ClearListView(hwndListView);
		InitListView64(buffer, 0, dwFileLength);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_DOS_HEADER"))              // 点击 DOS Header 响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_DOS_HEADER64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_NT_HEADERS64"))            // 点击 NT Header 响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_NT_HEADERS64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"NT Signature"))                  // 点击 NT 签名响应
	{
		ClearListView(hwndListView);
		CLICK_NT_Signature64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_FILE_HEADER"))             // 点击 File Header 响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_FILE_HEADER64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_OPTIONAL_HEADER64"))	    // 点击 Optional Header 响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_OPTIONAL_HEADER64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_SECTION_HEADERS"))         // 点击 Section Headers 响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_SECTION_HEADERS64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_EXPORT_DIRECTORY"))		// 点击导出目录响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_EXPORT_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_IMPORT_DIRECTORY"))		// 点击导入目录响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_IMPORT_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_RESOURCE_DIRECTORY"))		// 点击资源目录响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_RESOURCE_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_EXCEPTION_DIRECTORY"))		// 点击异常目录响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_EXCEPTION_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_CERTIFICATE_DIRECTORY"))		// 点击安全目录响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_CERTIFICATE_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_BASE_RELOC_DIRECTORY"))		// 点击重定位表响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_BASE_RELOC_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_DEBUG_DIRECTORY"))			// 点击调试目录响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_DEBUG_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_ARCHITECTURE_DIRECTORY"))	// 点击架构特定数据响应
	{
		ClearListView(hwndListView);
		MessageBox(NULL, L"该目录理应为空，请仔细查看二进制流是否被篡改！", szText, MB_OK);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_GLOBALPTR_DIRECTORY"))		// 点击全局指针响应
	{
		ClearListView(hwndListView);
		MessageBox(NULL, L"该目录理应为空，请仔细查看二进制流是否被篡改！", szText, MB_OK);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_TLS_DIRECTORY"))			// 点击TLS目录响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_TLS_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_LOAD_CONFIG_DIRECTORY"))	// 点击加载配置目录响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_LOAD_CONFIG_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_BOUND_IMPORT_DIRECTORY"))	// 点击绑定导入目录响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_BOUND_IMPORT_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_IAT_DIRECTORY"))			// 点击导入地址表（IAT）响应
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_IAT_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_DELAY_IMPORT_DIRECTORY"))	// 点击延迟加载导入描述符响应
	{
	ClearListView(hwndListView);
	CLICK_IMAGE_DELAY_IMPORT_DIRECTORY64(buffer);
	SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_COM_DESCRIPTOR_DIRECTORY"))// 点击 COM 运行时描述符响应
	{
	ClearListView(hwndListView);
	CLICK_IMAGE_COM_DESCRIPTOR_DIRECTORY64(buffer);
	SetStatusText(hwndStatus, szText);
	}
	else                                                        // 点击 Section 子项时响应
	{
	ClearListView(hwndListView);
	CLICK_SECTION_LIST64(buffer, szText);
	SetStatusText(hwndStatus, szText);
	}
}

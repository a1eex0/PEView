#pragma once

#include "framework.h"
#include "PEView.h"


// �˴���ģ���а����ĺ�����ǰ������:
VOID InitTreeView64(PCHAR buffer, LPWSTR lpFileName);
VOID InitListView64(PCHAR buffer, DWORD dwStart, DWORD dwReadLength);


//
//  ����: FormatMain64(HWND hWnd, PCHAR buffer, LPWSTR lpFilePath)
//
//  Ŀ��: PE64�ļ�����������
//
VOID FormatMain64(HWND hWnd, PCHAR buffer, LPWSTR lpFilePath)
{
	MessageBox(hwndListView, L"����һ�� PE64/PE32+ ����", L"��ʾ", MB_OK);
	InitTreeView64(buffer, szFileName);
	/*InitListView64(buffer,0,dwFileLength);*/
	SetStatusText(hwndStatus, szFileName);
}

//
//  ����: InitTreeView64(PCHAR buffer, LPWSTR lpFileName)
//
//  Ŀ��: ��������ͼ��ʾ����
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

	// �������ͼ�ĸ��ڵ�
	hRoot = AddItemToTree(hwndTreeView, lpFileName, NULL, TRUE);
	// ��� Dos ͷ�ڵ�
	hDosHeader = AddItemToTree(hwndTreeView, L"IMAGE_DOS_HEADER", hRoot, FALSE);
	// ��� NT ͷ�ڵ�
	hNTHeaders = AddItemToTree(hwndTreeView, L"IMAGE_NT_HEADERS64", hRoot, TRUE);
	// Ϊ NT ͷ����ӽڵ�
	hNTSignature = AddItemToTree(hwndTreeView, L"NT Signature", hNTHeaders, FALSE);
	hNTFileHeader = AddItemToTree(hwndTreeView, L"IMAGE_FILE_HEADER", hNTHeaders, FALSE);
	hNTOptionalHeader = AddItemToTree(hwndTreeView, L"IMAGE_OPTIONAL_HEADER64", hNTHeaders, FALSE);
	// ��� Section �ڵ�
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
		// �� PBYTE ת��Ϊ LPWSTR
		memset(strSectionName, 0, sizeof(strSectionName));
		MultiByteToWideChar(CP_ACP, 0, (PCHAR)pSection[i].Name, strlen((PCHAR)pSection[i].Name) + 1, strSectionName, sizeof(strSectionName) / sizeof(strSectionName[0]));
		// ��� Section �ӽڵ�
		AddItemToTree(hwndTreeView, strSectionName, hSectionHeaders, FALSE);

		// ƴ�ӽ���������ͼ�е���ʾ����
		wcscpy_s(strNameBuffer, L"SECTION");
		wcscat_s(strNameBuffer, strSectionName);

		BOOL bTableinSection = FALSE;
		BOOL bTableNum[0xF];
		// �жϱ�Ŀ¼�Ƿ��ڵ�ǰ����
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
			// ��Ӹ��ӽڵ�������ͼ���б���
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
	// ���ڵ�����Ϊչ��
	TreeView_Expand(hwndTreeView, hRoot, TVE_EXPAND);
	TreeView_Expand(hwndTreeView, hNTHeaders, TVE_EXPAND);
	TreeView_Expand(hwndTreeView, hSectionHeaders, TVE_EXPAND);
}

//
//  ����: InitListView64(PCHAR buffer, DWORD dwStart, DWORD dwReadLength)
//
//  Ŀ��: �����б���ͼ��ʾ�ļ�ʮ����������
//
VOID InitListView64(PCHAR buffer, DWORD dwStart, DWORD dwReadLength)
{
	HextoList(buffer, dwStart, dwReadLength);
}

//
//  ����: CLICK_IMAGE_DOS_HEADER64(PCHAR buffer)
//
//  Ŀ��: DOS ͷ�б���ʾ����
//
VOID CLICK_IMAGE_DOS_HEADER64(PCHAR buffer)
{
	WCHAR strBuffer[9];
	// ��ӷ���
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 250);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 200);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;

	AddListViewRow(hwndListView, 0, 0);
	_stprintf_s(strBuffer, L"%04X", pDos->e_magic);
	ListView_SetItemText(hwndListView, 0, 1, strBuffer);
	ListView_SetItemText(hwndListView, 0, 2, L"DOS ǩ��");
	_stprintf_s(strBuffer, L"%c%c", WCHAR(pDos->e_magic&0xFF),WCHAR(pDos->e_magic>>8));
	ListView_SetItemText(hwndListView, 0, 3, strBuffer);
		
	AddListViewRow(hwndListView, 1, 2);
	_stprintf_s(strBuffer, L"%04X", pDos->e_cblp);
	ListView_SetItemText(hwndListView, 1, 1, strBuffer);
	ListView_SetItemText(hwndListView, 1, 2, L"�ļ����һҳ���ֽ���");

	AddListViewRow(hwndListView, 2, 4);
	_stprintf_s(strBuffer, L"%04X", pDos->e_cp);
	ListView_SetItemText(hwndListView, 2, 1, strBuffer);
	ListView_SetItemText(hwndListView, 2, 2, L"�ļ��е�ҳ��");

	AddListViewRow(hwndListView, 3, 6);
	_stprintf_s(strBuffer, L"%04X", pDos->e_crlc);
	ListView_SetItemText(hwndListView, 3, 1, strBuffer);
	ListView_SetItemText(hwndListView, 3, 2, L"�ض�λ");

	AddListViewRow(hwndListView, 4, 8);
	_stprintf_s(strBuffer, L"%04X", pDos->e_cparhdr);
	ListView_SetItemText(hwndListView, 4, 1, strBuffer);
	ListView_SetItemText(hwndListView, 4, 2, L"�������Ĵ�С");

	AddListViewRow(hwndListView, 5, 10);
	_stprintf_s(strBuffer, L"%04X", pDos->e_minalloc);
	ListView_SetItemText(hwndListView, 5, 1, strBuffer);
	ListView_SetItemText(hwndListView, 5, 2, L"������Ҫ����Ķ���");

	AddListViewRow(hwndListView, 6, 12);
	_stprintf_s(strBuffer, L"%04X", pDos->e_maxalloc);
	ListView_SetItemText(hwndListView, 6, 1, strBuffer);
	ListView_SetItemText(hwndListView, 6, 2, L"�����Ҫ����Ķ���");

	AddListViewRow(hwndListView, 7, 14);
	_stprintf_s(strBuffer, L"%04X", pDos->e_ss);
	ListView_SetItemText(hwndListView, 7, 1, strBuffer);
	ListView_SetItemText(hwndListView, 7, 2, L"��ʼ����ԣ�SS ֵ");

	AddListViewRow(hwndListView, 8, 16);
	_stprintf_s(strBuffer, L"%04X", pDos->e_sp);
	ListView_SetItemText(hwndListView, 8, 1, strBuffer);
	ListView_SetItemText(hwndListView, 8, 2, L"��ʼ SP ֵ");

	AddListViewRow(hwndListView, 9, 18);
	_stprintf_s(strBuffer, L"%04X", pDos->e_csum);
	ListView_SetItemText(hwndListView, 9, 1, strBuffer);
	ListView_SetItemText(hwndListView, 9, 2, L"У���");

	AddListViewRow(hwndListView, 10, 20);
	_stprintf_s(strBuffer, L"%04X", pDos->e_ip);
	ListView_SetItemText(hwndListView, 10, 1, strBuffer);
	ListView_SetItemText(hwndListView, 10, 2, L"��ʼ IP ֵ");

	AddListViewRow(hwndListView, 11, 22);
	_stprintf_s(strBuffer, L"%04X", pDos->e_cs);
	ListView_SetItemText(hwndListView, 11, 1, strBuffer);
	ListView_SetItemText(hwndListView, 11, 2, L"��ʼ����ԣ�CS ֵ");

	AddListViewRow(hwndListView, 12, 24);
	_stprintf_s(strBuffer, L"%04X", pDos->e_lfarlc);
	ListView_SetItemText(hwndListView, 12, 1, strBuffer);
	ListView_SetItemText(hwndListView, 12, 2, L"�ض�λ����ļ���ַ");

	AddListViewRow(hwndListView, 13, 26);
	_stprintf_s(strBuffer, L"%04X", pDos->e_ovno);
	ListView_SetItemText(hwndListView, 13, 1, strBuffer);
	ListView_SetItemText(hwndListView, 13, 2, L"���ӱ��");

	AddListViewRow(hwndListView, 14, 28);
	ListView_SetItemText(hwndListView, 14, 1, L"e_res[4]");
	ListView_SetItemText(hwndListView, 14, 2, L"�����֣�8�ֽڣ�");

	AddListViewRow(hwndListView, 15, 36);
	_stprintf_s(strBuffer, L"%04X", pDos->e_oemid);
	ListView_SetItemText(hwndListView, 15, 1, strBuffer);
	ListView_SetItemText(hwndListView, 15, 2, L"OEM ��ʶ�������� e_oeminfo��");

	AddListViewRow(hwndListView, 16, 38);
	_stprintf_s(strBuffer, L"%04X", pDos->e_oeminfo);
	ListView_SetItemText(hwndListView, 16, 1, strBuffer);
	ListView_SetItemText(hwndListView, 16, 2, L"OEM ��Ϣ��e_oemid �ض���");

	AddListViewRow(hwndListView, 17, 40);
	ListView_SetItemText(hwndListView, 17, 1, L"e_res2[10]");
	ListView_SetItemText(hwndListView, 17, 2, L"�����֣�20�ֽڣ�");

	AddListViewRow(hwndListView, 18, 60);
	_stprintf_s(strBuffer, L"%08X", pDos->e_lfanew);
	ListView_SetItemText(hwndListView, 18, 1, strBuffer);
	ListView_SetItemText(hwndListView, 18, 2, L"�� exe ͷ�ļ���ַ");
}

//
//  ����: CLICK_IMAGE_NT_HEADERS64(PCHAR buffer)
//
//  Ŀ��: NT ͷʮ�������б���ʾ����
//
VOID CLICK_IMAGE_NT_HEADERS64(PCHAR buffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);
	HextoList(buffer, pDos->e_lfanew, (pNt->FileHeader.SizeOfOptionalHeader + 24));
}

//
//  ����: CLICK_NT_Signature64(PCHAR buffer)
//
//  Ŀ��: NT ͷǩ���б���ʾ����
//
VOID CLICK_NT_Signature64(PCHAR buffer)
{
	WCHAR strBuffer[9];
	// ��ӷ���
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 250);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 200);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);

	AddListViewRow(hwndListView, 0, pDos->e_lfanew);
	_stprintf_s(strBuffer, L"%08X", pNt->Signature);
	ListView_SetItemText(hwndListView, 0, 1, strBuffer);
	ListView_SetItemText(hwndListView, 0, 2, L"NT ͷǩ��");
	_stprintf_s(strBuffer, L"%c%c", WCHAR(pNt->Signature & 0xFF), WCHAR(pNt->Signature >> 8));
	ListView_SetItemText(hwndListView, 0, 3, strBuffer);
}

//
//  ����: CLICK_IMAGE_FILE_HEADER64(PCHAR buffer)
//
//  Ŀ��: �ļ�ͷ�б���ʾ����
//
VOID CLICK_IMAGE_FILE_HEADER64(PCHAR buffer)
{
	WCHAR strBuffer[27];
	// ��ӷ���
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 170);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 280);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);

	AddListViewRow(hwndListView, 0, pDos->e_lfanew + 4);
	_stprintf_s(strBuffer, L"%04X", pNt->FileHeader.Machine);
	ListView_SetItemText(hwndListView, 0, 1, strBuffer);
	ListView_SetItemText(hwndListView, 0, 2, L"������");
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
	ListView_SetItemText(hwndListView, 1, 2, L"������");

	AddListViewRow(hwndListView, 2, pDos->e_lfanew + 8);
	_stprintf_s(strBuffer, L"%08X", pNt->FileHeader.TimeDateStamp);
	ListView_SetItemText(hwndListView, 2, 1, strBuffer);
	ListView_SetItemText(hwndListView, 2, 2, L"����ʱ��");
	time_t datatime = pNt->FileHeader.TimeDateStamp;
	_wctime_s(strBuffer, 26, &datatime);
	ListView_SetItemText(hwndListView, 2, 3, strBuffer);

	AddListViewRow(hwndListView, 3, pDos->e_lfanew + 12);
	_stprintf_s(strBuffer, L"%08X", pNt->FileHeader.PointerToSymbolTable);
	ListView_SetItemText(hwndListView, 3, 1, strBuffer);
	ListView_SetItemText(hwndListView, 3, 2, L"���ű�ָ��");

	AddListViewRow(hwndListView, 4, pDos->e_lfanew + 16);
	_stprintf_s(strBuffer, L"%08X", pNt->FileHeader.NumberOfSymbols);
	ListView_SetItemText(hwndListView, 4, 1, strBuffer);
	ListView_SetItemText(hwndListView, 4, 2, L"���ű��еķ�����");

	AddListViewRow(hwndListView,5, pDos->e_lfanew + 20);
	_stprintf_s(strBuffer, L"%04X", pNt->FileHeader.SizeOfOptionalHeader);
	ListView_SetItemText(hwndListView, 5, 1, strBuffer);
	ListView_SetItemText(hwndListView, 5, 2, L"Optional ͷ����");

	AddListViewRow(hwndListView, 6, pDos->e_lfanew + 22);
	_stprintf_s(strBuffer, L"%04X", pNt->FileHeader.Characteristics);
	ListView_SetItemText(hwndListView, 6, 1, strBuffer);
	ListView_SetItemText(hwndListView, 6, 2, L"�ļ�����");
	DWORD line = 6;
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_RELOCS_STRIPPED, L"���ļ���ɾ���ض�λ��Ϣ");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_EXECUTABLE_IMAGE, L"�ļ��ǿ�ִ�е�");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_LINE_NUMS_STRIPPED, L"���ļ���ɾ�����к�");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_LOCAL_SYMS_STRIPPED, L"���ļ��а���ı��ط���");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_AGGRESIVE_WS_TRIM, L"�����޼�������");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_LARGE_ADDRESS_AWARE, L"Ӧ�ÿ��Դ��� >2GB ��ַ");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_LO)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_BYTES_REVERSED_LO, L"�������ֽڷ�ת");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_32BIT_MACHINE, L"32 λ�ֻ�");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_DEBUG_STRIPPED, L"�� .DBG �ļ��а���ĵ�����Ϣ");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, L"���ڿ��ƶ�ý���ϸ��Ʋ�����");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_NET_RUN_FROM_SWAP, L"���������ϸ��Ʋ�����");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_SYSTEM)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_SYSTEM, L"ϵͳ�ļ�");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_DLL)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_DLL, L"DLL �ļ�");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_UP_SYSTEM_ONLY, L"�ļ�ֻ���� UP ����������");
	}
	if (pNt->FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_HI)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_FILE_BYTES_REVERSED_HI, L"�������ֽڷ�ת");
	}
}

//
//  ����: CLICK_IMAGE_OPTIONAL_HEADER64(PCHAR buffer)
//
//  Ŀ��: �ļ�ͷ�б���ʾ����
//
VOID CLICK_IMAGE_OPTIONAL_HEADER64(PCHAR buffer)
{
	WCHAR strBuffer[27];
	// ��ӷ���
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
	AddListViewColumn(hwndListView, 0, 2, L"Description", 250);
	AddListViewColumn(hwndListView, 0, 3, L"Value", 200);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + buffer);

	DWORD offsetAddr = pDos->e_lfanew + 24;	// ��ַƫ��������ַ
	DWORD line = 0;							// ����������

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.Magic);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"��־λ");
	ListView_SetItemText(hwndListView, line, 3, L"PE64/PE32+");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%02X", pNt->OptionalHeader.MajorLinkerVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"���������汾��");

	line += 1;
	offsetAddr += 1;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%02X", pNt->OptionalHeader.MinorLinkerVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�������ΰ汾��");

	line += 1;
	offsetAddr += 1;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfCode);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"���к��д���������С");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfInitializedData);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"���г�ʼ�����������С");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfUninitializedData);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"����δ��ʼ�����������С");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.AddressOfEntryPoint);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"����ִ����� RVA");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.BaseOfCode);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"����������ʼ RVA");

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
	ListView_SetItemText(hwndListView, line, 2, L"����Ĭ���������ַ");

	line += 1;
	offsetAddr += 8;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SectionAlignment);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�ڴ�������Ķ���ֵ");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.FileAlignment);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�ļ�������Ķ���ֵ");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MajorOperatingSystemVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"����ϵͳ���汾��");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MinorOperatingSystemVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"����ϵͳ�ΰ汾��");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MajorImageVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�û��Զ������汾��");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MinorImageVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�û��Զ���ΰ汾��");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MajorSubsystemVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"������ϵͳ���汾��");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.MinorSubsystemVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"������ϵͳ�ΰ汾��");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.Win32VersionValue);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Win32 �汾ֵ��������ͨ��Ϊ0��");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfImage);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ӳ�������ڴ����ܳߴ�");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.SizeOfHeaders);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"DOS ͷ��PE ͷ��������ܴ�С");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.CheckSum);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ӳ��У���");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.Subsystem);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�ļ�Ӧ������");
	switch (pNt->OptionalHeader.Subsystem)
	{
	case IMAGE_SUBSYSTEM_NATIVE:
		wcscpy_s(strBuffer, L"���������ϵͳ����");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		wcscpy_s(strBuffer, L"ͼ�λ�Ӧ�ó���GUI��");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		wcscpy_s(strBuffer, L"����̨Ӧ�ó���CUI��");
		break;
	default:
		wcscpy_s(strBuffer, L"δ֪Ӧ�ó�������");
		break;
	}
	ListView_SetItemText(hwndListView, line, 3, strBuffer);

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pNt->OptionalHeader.DllCharacteristics);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"��ʾ DLL ���Ե����");
	if (pNt->OptionalHeader.DllCharacteristics& IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, L"���Դ������ 64 λ�����ַ�ռ�");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, L"DLL ���ö�̬����ַ");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, L"���������Լ��");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_NX_COMPAT, L"�� NX ����");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, L"����������");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_NO_SEH, L"������ SEH");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_NO_BIND, L"���󶨸��ļ�");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_APPCONTAINER, L"Ӧ���� AppContainer ��ִ��");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, L"����ʹ�� WDM ģ��");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_GUARD_CF, L"֧�ֿ���������");
	}
	if (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
	{
		line += 1;
		AddCharData(hwndListView, line, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, L"�ն˷�������֪");
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
	ListView_SetItemText(hwndListView, line, 2, L"��ʼ��ʱջ�Ĵ�С");

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
	ListView_SetItemText(hwndListView, line, 2, L"��ʼ��ʱʵ���ύջ�Ĵ�С");

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
	ListView_SetItemText(hwndListView, line, 2, L"��ʼ��ʱ�����ѵĴ�С");

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
	ListView_SetItemText(hwndListView, line, 2, L"��ʼ��ʱʵ�ʱ����ѵĴ�С");

	line += 1;
	offsetAddr += 8;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.LoaderFlags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�������أ�Ĭ��Ϊ0");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pNt->OptionalHeader.NumberOfRvaAndSizes);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"����Ŀ¼������");

	WCHAR* DataDirName[0xF] = {			// ����Ŀ¼�б�
		L"����Ŀ¼",
		L"����Ŀ¼",
		L"��ԴĿ¼",
		L"�쳣Ŀ¼",
		L"֤��Ŀ¼",
		L"��ַ�ض�λ��",
		L"����Ŀ¼",
		L"�ܹ��ض�����",
		L"ȫ��ָ��",
		L"TLSĿ¼",
		L"��������Ŀ¼",
		L"�󶨵���Ŀ¼",
		L"�����ַ��IAT��",
		L"�ӳټ��ص���������",
		L"CLR ����ʱ������",
	};
	// ѭ����ʾĿ¼�б�
	for (size_t i = 0; i < pNt->OptionalHeader.NumberOfRvaAndSizes-1; i++)
	{
		PIMAGE_DATA_DIRECTORY pDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory+i);

		// ��һ�е��������ǰĿ¼��
		line += 1;
		AddListViewRow(hwndListView, line, 0xFFFFFFFF);
		_stprintf_s(strBuffer, L"----%X----", i);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"-----------------------------");
		ListView_SetItemText(hwndListView, line, 3, L"----------------------");
		// �ڶ�����������ַ
		if (i == 4)
		{
			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(strBuffer, L"%08X", pDir->VirtualAddress);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"�ļ�ƫ�Ƶ�ַ");
			ListView_SetItemText(hwndListView, line, 3, DataDirName[i]);
		}
		else
		{
			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(strBuffer, L"%08X", pDir->VirtualAddress);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"�ڴ������ַ��RVA��");
			ListView_SetItemText(hwndListView, line, 3, DataDirName[i]);
		}
		// ���������Ŀ¼��С
		line += 1;
		offsetAddr += 4;
		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDir->Size);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"Ŀ¼��С");
	}
	// ��ʾ���һ������Ŀ¼
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
	ListView_SetItemText(hwndListView, line, 2, L"�ڴ������ַ��RVA��");
	ListView_SetItemText(hwndListView, line, 3, L"����Ŀ¼");
	// ���������Ŀ¼��С
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDir->Size);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Ŀ¼��С");
}
	
//
//  ����: CLICK_IMAGE_SECTION_HEADERS64(PCHAR buffer)
//
//  Ŀ��: ����ʮ�������б���ʾ����
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
//  ����: CLICK_IMAGE_EXPORT_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: �������б���ʾ����
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
		MessageBox(hwndListView, L"������Ϊ��", L"��ʾ", MB_OK);
		return;
	}

	DWORD offsetAddr = RvaToOffset(pExportDir->VirtualAddress, buffer);	// ��ַƫ��������ַ
	DWORD line = 0;							// ����������
	WCHAR strBuffer[9];

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->Characteristics);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"������");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->TimeDateStamp);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ʱ������");
	time_t datatime = pExport->TimeDateStamp;
	WCHAR timeBuffer[27];
	_wctime_s(timeBuffer, 26, &datatime);
	ListView_SetItemText(hwndListView, line, 3, timeBuffer);

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->MajorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"���汾�ţ�һ��Ϊ0");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->MinorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�ΰ汾�ţ�һ��Ϊ0");

	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->Name);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ģ�����ʵ���� RVA");

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
	ListView_SetItemText(hwndListView, line, 2, L"����");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->NumberOfFunctions);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�������������");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->NumberOfNames);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"��������������");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->AddressOfFunctions);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"����������ַ�� RVA");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->AddressOfNames);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�����������Ʊ� RVA");

	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pExport->AddressOfNameOrdinals);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"���кű� RVA");

	line += 1;
	AddListViewRow(hwndListView, line, 0xFFFFFFFF);
	_stprintf_s(strBuffer, L"%08X", 0xFFFFFFFF);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"=====����������ַ��=====");
	ListView_SetItemText(hwndListView, line, 3, L"=====�����������Ʊ�=====");

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
//  ����: CLICK_IMAGE_IMPORT_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: ����Ŀ¼�б���ʾ����
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
		ListView_SetItemText(hwndListView, line, 2, L"�������Ʊ�� RVA");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pImport->TimeDateStamp);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"ʱ������");
		time_t datatime = pImport->TimeDateStamp;
		WCHAR timeBuffer[27];
		_wctime_s(timeBuffer, 26, &datatime);
		ListView_SetItemText(hwndListView, line, 3, timeBuffer);
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pImport->ForwarderChain);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"API ����������");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pImport->Name);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"DLL ����ָ���ַ RVA");
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
		ListView_SetItemText(hwndListView, line, 2, L"�����ַ��� RVA ");
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
//  ����: CLICK_IMAGE_RESOURCE_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: ��ԴĿ¼�б���ʾ����
//
VOID CLICK_IMAGE_RESOURCE_DIRECTORY64(PCHAR buffer)
{
	PWCHAR pResType[0x19] = {
		L"NULL",
		L"���ָ��",
		L"λͼ",
		L"ͼ��",
		L"�˵�",
		L"�Ի���",
		L"�ַ����б�",
		L"����Ŀ¼",
		L"����",
		L"��ݼ�",
		L"�Ǹ�ʽ����Դ",
		L"��Ϣ�б�",
		L"���ָ����",
		L"NULL",
		L"ͼ����",
		L"NULL",
		L"�汾��Ϣ",
		L"DLGINCLUDE",
		L"NULL",
		L"PLUGPLAY",
		L"VXD",
		L"��ָ̬��",
		L"��̬ͼ��",
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
	ListView_SetItemText(hwndListView, line, 2, L"���Ա�־");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pResource->TimeDateStamp);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ʱ������");
	time_t datatime = pResource->TimeDateStamp;
	WCHAR timeBuffer[27];
	_wctime_s(timeBuffer, 26, &datatime);
	ListView_SetItemText(hwndListView, line, 3, timeBuffer);
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pResource->MajorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"���汾��");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pResource->MinorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�ΰ汾��");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pResource->NumberOfNamedEntries);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"���Ƶ���Դ��Ŀ����");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pResource->NumberOfIdEntries);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ID ����Դ��Ŀ����");
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
						ListView_SetItemText(hwndListView, line, 2, L"��Դƫ�Ƶ�ַ RVA");
						ListView_SetItemText(hwndListView, line, 3, strNameBuffer2);
						line += 1;
						offsetAddr += 4;

						AddListViewRow(hwndListView, line, offsetAddr);
						_stprintf_s(strBuffer, L"%08X", pData->Size);
						ListView_SetItemText(hwndListView, line, 1, strBuffer);
						ListView_SetItemText(hwndListView, line, 2, L"��Դ����");
						line += 1;
						offsetAddr += 4;

						AddListViewRow(hwndListView, line, offsetAddr);
						_stprintf_s(strBuffer, L"%08X", pData->CodePage);
						ListView_SetItemText(hwndListView, line, 1, strBuffer);
						ListView_SetItemText(hwndListView, line, 2, L"����ҳ");
						line += 1;
						offsetAddr += 4;

						AddListViewRow(hwndListView, line, offsetAddr);
						_stprintf_s(strBuffer, L"%08X", pData->Reserved);
						ListView_SetItemText(hwndListView, line, 1, strBuffer);
						ListView_SetItemText(hwndListView, line, 2, L"�����ֶ�");
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
//  ����: CLICK_IMAGE_EXCEPTION_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: �쳣Ŀ¼�б���ʾ����
//
VOID CLICK_IMAGE_EXCEPTION_DIRECTORY64(PCHAR buffer)
{
	AddListViewColumn(hwndListView, 0, 0, L"pFile", 75);
	AddListViewColumn(hwndListView, 1, 1, L"��ʼ��ַ[RVA]", 120);
	AddListViewColumn(hwndListView, 1, 2, L"������ַ[RVA]", 120);
	AddListViewColumn(hwndListView, 1, 3, L"unwind��ַ[RVA]", 150);

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
//  ����: CLICK_IMAGE_CERTIFICATE_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: ֤��Ŀ¼�б���ʾ����
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
		ListView_SetItemText(hwndListView, line, 2, L"֤��鳤��");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%04X", pCertTable->wRevision);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"֤��汾");
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
		ListView_SetItemText(hwndListView, line, 2, L"֤������");
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
		ListView_SetItemText(hwndListView, line, 2, L"֤������");
		ListView_SetItemText(hwndListView, line, 3, L"pFile:������ʼ��ַ��Data:���ݽ�����ַ");
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
//  ����: CLICK_IMAGE_BASE_RELOC_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: �ض�λĿ¼�б���ʾ����
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
				// �� PBYTE ת��Ϊ LPWSTR
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
		ListView_SetItemText(hwndListView, line, 2, L"�����ض�λ��ַ RVA");
		ListView_SetItemText(hwndListView, line, 3, strSectionName);
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pReloc->SizeOfBlock);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"��ǰ�ض�λ���С");
		_stprintf_s(strBuffer, L"��ǰ��������%X", dwCount);
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
//  ����: CLICK_IMAGE_DEBUG_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: ����Ŀ¼�б���ʾ����
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
	ListView_SetItemText(hwndListView, line, 2, L"δʹ��");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDebug->TimeDateStamp);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ʱ������");
	time_t datatime = pDebug->TimeDateStamp;
	WCHAR timeBuffer[27];
	_wctime_s(timeBuffer, 26, &datatime);
	ListView_SetItemText(hwndListView, line, 3, timeBuffer);
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pDebug->MajorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"���汾");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pDebug->MinorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�ΰ汾");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDebug->Type);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"������Ϣ����");
	switch (pDebug->Type)
	{
	case IMAGE_DEBUG_TYPE_UNKNOWN:
		wcscpy_s(strBuffer, L"���й��߶����Ե�δֵ֪");
		break;
	case IMAGE_DEBUG_TYPE_COFF:
		wcscpy_s(strBuffer, L"COFF ������Ϣ");
		break;
	case IMAGE_DEBUG_TYPE_CODEVIEW:
		wcscpy_s(strBuffer, L"Visual C++ ������Ϣ");
		break;
	case IMAGE_DEBUG_TYPE_FPO:
		wcscpy_s(strBuffer, L"ָ֡��ʡ�� (FPO) ��Ϣ");
		break;
	case IMAGE_DEBUG_TYPE_MISC:
		wcscpy_s(strBuffer, L"DBG �ļ���λ��");
		break;
	case IMAGE_DEBUG_TYPE_EXCEPTION:
		wcscpy_s(strBuffer, L".pdata ���ֵĸ���");
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
		wcscpy_s(strBuffer, L"PE ȷ���Ի�������");
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
	ListView_SetItemText(hwndListView, line, 2, L"�������ݴ�С");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDebug->AddressOfRawData);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�������ݵ��ڴ��ַ RVA");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pDebug->AddressOfRawData);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�������ݵ��ļ�ƫ�Ƶ�ַ");
	line += 1;
	offsetAddr += 4;
}

//
//  ����: CLICK_IMAGE_TLS_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: TLSĿ¼�б���ʾ����
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
	ListView_SetItemText(hwndListView, line, 2, L"��ʼ��ַ");
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
	ListView_SetItemText(hwndListView, line, 2, L"������ַ");
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
	ListView_SetItemText(hwndListView, line, 2, L"������ַ");
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
	ListView_SetItemText(hwndListView, line, 2, L"�ص���ַ");
	ListView_SetItemText(hwndListView, line, 3, L"PIMAGE_TLS_CALLBACK �ṹ");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pTLS->SizeOfZeroFill);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"������С");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pTLS->Characteristics);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"����");
	line += 1;
	offsetAddr += 4;
}

//
//  ����: CLICK_IMAGE_LOAD_CONFIG_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: ��������Ŀ¼�б���ʾ����
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
	ListView_SetItemText(hwndListView, line, 2, L"�ṹ�Ĵ�С");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->TimeDateStamp);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ʱ������");
	time_t datatime = pLoadConfig->TimeDateStamp;
	WCHAR timeBuffer[27];
	_wctime_s(timeBuffer, 26, &datatime);
	ListView_SetItemText(hwndListView, line, 3, timeBuffer);
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->MajorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"��Ҫ�汾��");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->MinorVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"��Ҫ�汾��");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->GlobalFlagsClear);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ȫ�ֱ�־���");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->GlobalFlagsSet);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"ȫ�ֱ�־����");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->CriticalSectionDefaultTimeout);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�ٽ���Ĭ�ϳ�ʱֵ");
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
	ListView_SetItemText(hwndListView, line, 2, L"����ǰ׺��");
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
	ListView_SetItemText(hwndListView, line, 2, L"�������С");
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
	ListView_SetItemText(hwndListView, line, 2, L"��ջ�ڴ���ֵ");
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
	ListView_SetItemText(hwndListView, line, 2, L"���̹�������");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->ProcessHeapFlags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"���̶ѱ�־");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->CSDVersion);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"������汾");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->DependentLoadFlags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"��ؼ��ر�־");
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
	ListView_SetItemText(hwndListView, line, 2, L"�༭�б�");
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
	ListView_SetItemText(hwndListView, line, 2, L"Cookie ָ��");
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
	ListView_SetItemText(hwndListView, line, 2, L"SE ��������");
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
	ListView_SetItemText(hwndListView, line, 2, L"SE �����������");
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
	ListView_SetItemText(hwndListView, line, 2, L"�洢������������麯��ָ��");
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
	ListView_SetItemText(hwndListView, line, 2, L"�洢�������������Ⱥ���ָ��");
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
	ListView_SetItemText(hwndListView, line, 2, L"����������������");
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
	ListView_SetItemText(hwndListView, line, 2, L"������������������");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->GuardFlags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"������������ر�־");
	line += 1;
	offsetAddr += 4;

	PIMAGE_LOAD_CONFIG_CODE_INTEGRITY pCI = (PIMAGE_LOAD_CONFIG_CODE_INTEGRITY)(offsetAddr + buffer);
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pCI->Flags);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"��־λ");
	ListView_SetItemText(hwndListView, line, 3, L"Flags PIMAGE_LOAD_CONFIG_CODE_INTEGRITY");
	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pCI->Catalog);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Ŀ¼����");
	ListView_SetItemText(hwndListView, line, 3, L"Catalog PIMAGE_LOAD_CONFIG_CODE_INTEGRITY");
	line += 1;
	offsetAddr += 2;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pCI->CatalogOffset);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"Ŀ¼ƫ��");
	ListView_SetItemText(hwndListView, line, 3, L"CatalogOffset PIMAGE_LOAD_CONFIG_CODE_INTEGRITY");
	line += 1;
	offsetAddr += 4;
	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pCI->Reserved);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"������");
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
	ListView_SetItemText(hwndListView, line, 2, L"�洢������������ַȡIAT��");
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
	ListView_SetItemText(hwndListView, line, 2, L"�洢������������ַȡIAT�����");
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
	ListView_SetItemText(hwndListView, line, 2, L"��������������תĿ���");
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
	ListView_SetItemText(hwndListView, line, 2, L"��������������תĿ������");
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
	ListView_SetItemText(hwndListView, line, 2, L"��̬�ض�λ��");
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
	ListView_SetItemText(hwndListView, line, 2, L"CHPEԪ����ָ��");
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
	ListView_SetItemText(hwndListView, line, 2, L"����������������");
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
	ListView_SetItemText(hwndListView, line, 2, L"���������������̼���");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->DynamicValueRelocTableOffset);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"��̬�ض�λ��ƫ��");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->DynamicValueRelocTableSection);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"��̬�ض�λ���");
	line += 1;
	offsetAddr += 2;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%04X", pLoadConfig->Reserved2);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"������");
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
	ListView_SetItemText(hwndListView, line, 2, L"����������֤��ջָ�뺯��ָ��");
	line += 1;
	offsetAddr += 8;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->HotPatchTableOffset);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"�Ȳ�����ƫ��");
	line += 1;
	offsetAddr += 4;

	AddListViewRow(hwndListView, line, offsetAddr);
	_stprintf_s(strBuffer, L"%08X", pLoadConfig->Reserved3);
	ListView_SetItemText(hwndListView, line, 1, strBuffer);
	ListView_SetItemText(hwndListView, line, 2, L"������");
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
	ListView_SetItemText(hwndListView, line, 2, L"Enclave ����ָ��");
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
	ListView_SetItemText(hwndListView, line, 2, L"��ʧ��Ԫ����ָ��");
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
	ListView_SetItemText(hwndListView, line, 2, L"EH ������");
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
	ListView_SetItemText(hwndListView, line, 2, L"EH ���������");
	line += 1;
	offsetAddr += 8;
}

//
//  ����: CLICK_IMAGE_BOUND_IMPORT_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: �󶨵���Ŀ¼�б���ʾ����
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
		ListView_SetItemText(hwndListView, line, 2, L"ʱ������");
		time_t datatime = pBound->TimeDateStamp;
		WCHAR timeBuffer[27];
		_wctime_s(timeBuffer, 26, &datatime);
		ListView_SetItemText(hwndListView, line, 3, timeBuffer);
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%04X", pBound->OffsetModuleName);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"ģ������");
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
		ListView_SetItemText(hwndListView, line, 2, L"REF ����");
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
			ListView_SetItemText(hwndListView, line, 2, L"ʱ������");
			datatime = pREF->TimeDateStamp;
			_wctime_s(timeBuffer, 26, &datatime);
			ListView_SetItemText(hwndListView, line, 3, timeBuffer);
			line += 1;
			offsetAddr += 4;

			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(strBuffer, L"%04X", pREF->OffsetModuleName);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"ģ������");
			szName = (PCHAR)(pREF->OffsetModuleName + dwOffset + buffer);
			memset(strNameBuffer, 0, sizeof(strNameBuffer));
			MultiByteToWideChar(CP_ACP, 0, szName, strlen(szName) + 1, strNameBuffer, sizeof(strNameBuffer) / sizeof(strNameBuffer[0]));
			ListView_SetItemText(hwndListView, line, 3, strNameBuffer);
			line += 1;
			offsetAddr += 2;

			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(strBuffer, L"%04X", pREF->Reserved);
			ListView_SetItemText(hwndListView, line, 1, strBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"������");
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
//  ����: CLICK_IMAGE_IAT_DIRECTORY64(PCHAR buffer)
//
//  Ŀ��: �����ַ���б���ʾ����
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
//  ����: CLICK_IMAGE_DELAY_IMPORT_DIRECTORY64(PCHAR buffer, LPWSTR szText)
//
//  Ŀ��: �ӳټ��ص���Ŀ¼�б���ʾ����
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
		ListView_SetItemText(hwndListView, line, 2, L"����");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->DllNameRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"ģ������");
		szName = (PCHAR)(RvaToOffset(pDelayImport->DllNameRVA, buffer) + buffer);
		memset(strNameBuffer, 0, sizeof(strNameBuffer));
		MultiByteToWideChar(CP_ACP, 0, szName, strlen(szName) + 1, strNameBuffer, sizeof(strNameBuffer) / sizeof(strNameBuffer[0]));
		ListView_SetItemText(hwndListView, line, 3, strNameBuffer);
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->ModuleHandleRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"ģ����");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->ImportAddressTableRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"�ӳٵ����ַ��");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->ImportNameTableRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"�ӳٵ������Ʊ�");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->BoundImportAddressTableRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"���ӳٵ����");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->UnloadInformationTableRVA);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"ж���ӳٵ����");
		line += 1;
		offsetAddr += 4;

		AddListViewRow(hwndListView, line, offsetAddr);
		_stprintf_s(strBuffer, L"%08X", pDelayImport->TimeDateStamp);
		ListView_SetItemText(hwndListView, line, 1, strBuffer);
		ListView_SetItemText(hwndListView, line, 2, L"ʱ������");
		datatime = pDelayImport->TimeDateStamp;
		_wctime_s(timeBuffer, 26, &datatime);
		ListView_SetItemText(hwndListView, line, 3, timeBuffer);
		line += 1;
		offsetAddr += 4;

		pDelayImport++;
	}

	
}

//
//  ����: CLICK_IMAGE_COM_DESCRIPTOR_DIRECTORY64(PCHAR buffer, LPWSTR szText)
//
//  Ŀ��: COM ����Ŀ¼�б���ʾ����
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
//  ����: CLICK_SECTION_LIST64(PCHAR buffer, LPWSTR szText)
//
//  Ŀ��: ���������б���ʾ����
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
		// �� PBYTE ת��Ϊ LPWSTR
		memset(strSectionName, 0, sizeof(strSectionName));
		MultiByteToWideChar(CP_ACP, 0, (PCHAR)pSection[i].Name, strlen((PCHAR)pSection[i].Name) + 1, strSectionName, sizeof(strSectionName) / sizeof(strSectionName[0]));
		wcscat_s(strBuffer, strSectionName);
		if (!wcscmp(szText, strSectionName))			// ��� SECTION ͷ�ڽ����б���ʾ���
		{
			// ��ӷ���
			AddListViewColumn(hwndListView, 1, 0, L"pFile", 75);
			AddListViewColumn(hwndListView, 1, 1, L"Data", 100);
			AddListViewColumn(hwndListView, 0, 2, L"Description", 270);
			AddListViewColumn(hwndListView, 0, 3, L"Value", 180);

			WCHAR dataBuffer[9];

			// ��ַƫ��������ַ
			DWORD offsetAddr = pDos->e_lfanew + 24 + pNt->FileHeader.SizeOfOptionalHeader + (i * 40);
			DWORD line = 0;		// ����������

			AddListViewRow(hwndListView, line, offsetAddr);
			ListView_SetItemText(hwndListView, line, 2, L"������");
			ListView_SetItemText(hwndListView, line, 3, strSectionName);

			line += 1;
			offsetAddr += 8;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].Misc.VirtualSize);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"�ڴ��еĴ�С");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].VirtualAddress);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"�������ʼ��ַ RVA");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].SizeOfRawData);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"�����ļ��н�����ռ��С");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].PointerToRawData);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"�����ļ��н�����ʼλ��");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].PointerToRelocations);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"�� OBJ �ļ���ʹ�ã��ض�λ��ƫ��");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].PointerToLinenumbers);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"�кű��ƫ�ƣ������ã�");

			line += 1;
			offsetAddr += 4;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%04X", pSection[i].NumberOfRelocations);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"�� OBJ �ļ���ʹ�ã��ض�λ������");

			line += 1;
			offsetAddr += 2;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%04X", pSection[i].NumberOfLinenumbers);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"�кű����кŵ�����");

			line += 1;
			offsetAddr += 2;
			AddListViewRow(hwndListView, line, offsetAddr);
			_stprintf_s(dataBuffer, L"%08X", pSection[i].Characteristics);
			ListView_SetItemText(hwndListView, line, 1, dataBuffer);
			ListView_SetItemText(hwndListView, line, 2, L"���������");
			if (pSection[i].Characteristics & IMAGE_SCN_CNT_CODE)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_CNT_CODE, L"�����������");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_CNT_INITIALIZED_DATA, L"���������ʼ������");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_CNT_UNINITIALIZED_DATA, L"�������δ��ʼ������");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_LNK_INFO)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_LNK_INFO, L"�������ע�ͻ��������͵���Ϣ");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_LNK_REMOVE)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_LNK_REMOVE, L"�������ݲ����Ϊ�����һ����");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_LNK_COMDAT)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_LNK_COMDAT, L"������� comdat");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_NO_DEFER_SPEC_EXC, L"���ô����� TLB ��Ŀ�е��Ʋ����쳣����λ");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_GPREL)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_GPREL, L"�������ݿɱ�GP����");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_LNK_NRELOC_OVFL, L"���������չ�ض�λ");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_DISCARDABLE, L"����ɱ�����");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_NOT_CACHED, L"���鲻�ɻ���");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_NOT_PAGED)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_NOT_PAGED, L"���鲻�ɷ�ҳ");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_SHARED)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_SHARED, L"����ɹ���");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_EXECUTE, L"�����ִ��");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_READ)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_READ, L"����ɶ�");
			}
			if (pSection[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			{
				line += 1;
				AddCharDataL(hwndListView, line, IMAGE_SCN_MEM_WRITE, L"�����д");
			}

			break;
		}
		if (!wcscmp(szText, strBuffer))				// �����Ŀ¼�� SECTION �������ʾ���
		{
			HextoList(buffer, pSection[i].PointerToRawData, pSection[i].SizeOfRawData);
			break;
		}
	}
}

//
//  ����: TreeToList64(PCHAR buffer, LPWSTR szText, LPWSTR lpFilePath)
//
//  Ŀ��: ����ͼ�ӽڵ��б���ͼ��Ӧ
//
VOID TreeToList64(PCHAR buffer, LPWSTR szText, LPWSTR lpFilePath)
{
	if (!wcscmp(szText, lpFilePath))                            // ����ļ�����Ӧ
	{
		ClearListView(hwndListView);
		InitListView64(buffer, 0, dwFileLength);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_DOS_HEADER"))              // ��� DOS Header ��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_DOS_HEADER64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_NT_HEADERS64"))            // ��� NT Header ��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_NT_HEADERS64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"NT Signature"))                  // ��� NT ǩ����Ӧ
	{
		ClearListView(hwndListView);
		CLICK_NT_Signature64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_FILE_HEADER"))             // ��� File Header ��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_FILE_HEADER64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_OPTIONAL_HEADER64"))	    // ��� Optional Header ��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_OPTIONAL_HEADER64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_SECTION_HEADERS"))         // ��� Section Headers ��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_SECTION_HEADERS64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_EXPORT_DIRECTORY"))		// �������Ŀ¼��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_EXPORT_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_IMPORT_DIRECTORY"))		// �������Ŀ¼��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_IMPORT_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_RESOURCE_DIRECTORY"))		// �����ԴĿ¼��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_RESOURCE_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_EXCEPTION_DIRECTORY"))		// ����쳣Ŀ¼��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_EXCEPTION_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_CERTIFICATE_DIRECTORY"))		// �����ȫĿ¼��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_CERTIFICATE_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_BASE_RELOC_DIRECTORY"))		// ����ض�λ����Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_BASE_RELOC_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_DEBUG_DIRECTORY"))			// �������Ŀ¼��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_DEBUG_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_ARCHITECTURE_DIRECTORY"))	// ����ܹ��ض�������Ӧ
	{
		ClearListView(hwndListView);
		MessageBox(NULL, L"��Ŀ¼��ӦΪ�գ�����ϸ�鿴���������Ƿ񱻴۸ģ�", szText, MB_OK);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_GLOBALPTR_DIRECTORY"))		// ���ȫ��ָ����Ӧ
	{
		ClearListView(hwndListView);
		MessageBox(NULL, L"��Ŀ¼��ӦΪ�գ�����ϸ�鿴���������Ƿ񱻴۸ģ�", szText, MB_OK);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_TLS_DIRECTORY"))			// ���TLSĿ¼��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_TLS_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_LOAD_CONFIG_DIRECTORY"))	// �����������Ŀ¼��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_LOAD_CONFIG_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_BOUND_IMPORT_DIRECTORY"))	// ����󶨵���Ŀ¼��Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_BOUND_IMPORT_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_IAT_DIRECTORY"))			// ��������ַ��IAT����Ӧ
	{
		ClearListView(hwndListView);
		CLICK_IMAGE_IAT_DIRECTORY64(buffer);
		SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_DELAY_IMPORT_DIRECTORY"))	// ����ӳټ��ص�����������Ӧ
	{
	ClearListView(hwndListView);
	CLICK_IMAGE_DELAY_IMPORT_DIRECTORY64(buffer);
	SetStatusText(hwndStatus, szText);
	}
	else if (!wcscmp(szText, L"IMAGE_COM_DESCRIPTOR_DIRECTORY"))// ��� COM ����ʱ��������Ӧ
	{
	ClearListView(hwndListView);
	CLICK_IMAGE_COM_DESCRIPTOR_DIRECTORY64(buffer);
	SetStatusText(hwndStatus, szText);
	}
	else                                                        // ��� Section ����ʱ��Ӧ
	{
	ClearListView(hwndListView);
	CLICK_SECTION_LIST64(buffer, szText);
	SetStatusText(hwndStatus, szText);
	}
}

// PEView.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "PEView.h"

#define MAX_LOADSTRING 100

// 全局变量:
HINSTANCE hInst;                                // 当前实例
WCHAR szTitle[MAX_LOADSTRING];                  // 标题栏文本
WCHAR szWindowClass[MAX_LOADSTRING];            // 主窗口类名
WCHAR szFilePath[MAX_LOADSTRING];               // 文件路径
HWND hwndMain;                                  // 主窗口句柄
HWND hwndTreeView, hwndListView, hwndStatus;    // 控件句柄
RECT rect, rcStatus, rcTree, rcList;            // 坐标结构声明
UINT uStatusHeight;                             // 状态栏高度存储

// 此代码模块中包含的函数的前向声明:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
DWORD               InitWindowControls(HWND hWnd);
RECT                RearrangeWindow(HWND hWnd);
DWORD               SlippageWindow(HWND hWnd, WORD wxPos);
BOOL                OnNotify(WPARAM wParam, LPARAM lParam);


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,             // 应用程序本次运行实例句柄
                     _In_opt_ HINSTANCE hPrevInstance,      // 应用程序之前的实例，始终为 NULL
                     _In_ LPWSTR    lpCmdLine,              // 命令行参数
                     _In_ int       nCmdShow)               // 窗口显示方式，SW_SHOW
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: 在此处放置代码。

    // 初始化全局字符串
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_PEVIEW, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // 执行应用程序初始化:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_PEVIEW));  // 获取菜单资源表的句柄

    if (wcslen(lpCmdLine))
    {
        FileMain(hwndMain, lpCmdLine);
    }
    else
    {
        OpenFileName(hwndMain, szFilePath);
        if (szFilePath[0] != NULL)
        {
            FileMain(hwndMain, szFilePath);
        }
    }
       
    MSG msg;

    // 主消息循环:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))     // 加速菜单资源表处理
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  函数: MyRegisterClass()
//
//  目标: 注册窗口类。
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;           // 初始化 WNDCLASSEXW 结构体

    wcex.cbSize = sizeof(WNDCLASSEX);                                           // 指定结构体大小，一般为sizeof(WNDCLASSEX)，在使用此结构提前必须赋值

    wcex.style          = CS_HREDRAW | CS_VREDRAW;                              // 指定窗口显示形式
    wcex.lpfnWndProc    = WndProc;                                              // 指定处理主窗口消息的函数
    wcex.cbClsExtra     = 0;                                                    // 遵循窗口类结构分配的额外字节数。系统将字节初始化为零
    wcex.cbWndExtra     = 0;                                                    // 在窗口实例之后分配的额外字节数。系统将字节初始化为零
    wcex.hInstance      = hInstance;                                            // 当前应用程序的实例句柄
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_PEVIEW));     // 类图标的句柄
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);                       // 类光标的句柄
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);                             // 类背景画笔的句柄
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_PEVIEW);                         // 指向类菜单资源的名称
    wcex.lpszClassName  = szWindowClass;                                        // 指定窗口类名
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL)); // 与窗口类关联的小图标的句柄

    return RegisterClassExW(&wcex);
}

//
//   函数: InitInstance(HINSTANCE, int)
//
//   目标: 保存实例句柄并创建主窗口
//
//   注释:
//
//        在此函数中，我们在全局变量中保存实例句柄并
//        创建和显示主程序窗口。
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // 将实例句柄存储在全局变量中

   HWND hWnd = CreateWindowW(
       szWindowClass,       // 主窗口类名
       szTitle,             // 窗口名
       WS_OVERLAPPEDWINDOW, // 窗口样式
       600,                 // 水平位置
       200,                 // 垂直位置
       930,                 // 宽
       650,                 // 高
       nullptr,             // 父窗口句柄（无父窗口）
       nullptr,             // 菜单（无菜单）
       hInstance,           // 应用程序实例
       nullptr);            // 窗口创建数据（无窗口创建数据）
 
   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  函数: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  目标: 处理主窗口的消息。
//
//  WM_COMMAND  - 处理应用程序菜单
//  WM_PAINT    - 绘制主窗口
//  WM_DESTROY  - 发送退出消息并返回
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    hwndMain = hWnd;
    WORD wxPos;
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // 分析菜单选择:
            switch (wmId)
            {
            case IDM_OPENFILE:
                ClearListView(hwndListView);
                ClearTreeView(hwndTreeView);
                OpenFileName(hWnd, szFilePath);
                if (szFilePath[0] != NULL)
                {
                    FileMain(hwndMain, szFilePath);
                }
                break;
            case IDM_CLOSEFILE:
                ClearListView(hwndListView);
                ClearTreeView(hwndTreeView);
                SetStatusText(hwndStatus, L"PEView is Ready!");
                break;
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: 在此处添加使用 hdc 的任何绘图代码...
            EndPaint(hWnd, &ps);
        }
        break;
    // 创建窗口时运行
    case WM_CREATE:
        InitWindowControls(hWnd);
        break;
    // 窗口大小变更时运行
    case WM_SIZE:
        RearrangeWindow(hWnd);
        break;
    // 鼠标左键在窗口内按下
    case WM_LBUTTONDOWN:
        SetCapture(hWnd);       // 设置鼠标捕获（防止光标抛出窗口时区鼠标焦点）
        break;
    // 鼠标左键在窗口内按下
    case WM_LBUTTONUP:
        ReleaseCapture();       // 释放鼠标捕获
        break;
    // 当鼠标移动到分割栏时，设置光标图标，并根据滑动距离，重绘树视图与列表视图宽度
    case WM_MOUSEMOVE:
        SetClassLong(hWnd, GCL_HCURSOR, (LONG)LoadCursorW(NULL, IDC_SIZEWE)); // SetClassLong在进行编译时，GCL_HCURSOR为x86宏，GCLP_HCURSOR为x64宏，具体差异见winuser.h上下文
        wxPos = GET_X_LPARAM(lParam);
        if (wParam == MK_LBUTTON)
        {
            SlippageWindow(hWnd, wxPos);
        }
        break;
    // 鼠标点击时运行
    case WM_NOTIFY:
        OnNotify(wParam, lParam);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// “关于”框的消息处理程序。
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}


//
//  函数: InitWindowControls(HWND hWnd)
//
//  目标: 创建并初始化窗口控件
//
DWORD InitWindowControls(HWND hWnd)
{
    // 创建窗口控件
    hwndTreeView = CreateTreeView(hInst, hWnd, L"PETreeView");
    hwndListView = CreateListView(hInst, hWnd, L"PEListView");
    hwndStatus = CreateStatus(hInst, hWnd, L"PEView is Ready!");
    // 获取窗口及状态栏宽高
    GetClientRect(hWnd, &rect);
    GetClientRect(hwndStatus, &rcStatus);
    uStatusHeight = rcStatus.bottom - rcStatus.top;

    // 设置树视图宽高坐标
    MoveWindow(hwndTreeView,
        rect.left, rect.top,
        rect.right * 0.3, rect.bottom - uStatusHeight,
        TRUE);
    // 设置列表视图宽高坐标
    MoveWindow(hwndListView,
        rect.right * 0.3 + 3, rect.top,
        rect.right * 0.7 - 3, rect.bottom - uStatusHeight,
        TRUE);

    // 自定义显示字体(均为默认选项)
    HFONT hFont = CreateFont(
        0,                          // cHeight,
        0,                          // cWidth,
        0,                          // cEscapement,
        0,                          // cOrientation,
        0,                          // cWeight,
        0,                          // bItalic,
        0,                          // bUnderline,
        0,                          // bStrikeOut,
        DEFAULT_CHARSET,            // iCharSet,
        OUT_DEFAULT_PRECIS,         // iOutPrecision,
        CLIP_DEFAULT_PRECIS,        // iClipPrecision,
        DEFAULT_QUALITY,            // iQuality,
        FIXED_PITCH | FF_DONTCARE,  // iPitchAndFamily,
        NULL);                      // pszFaceName
    // 设置列表视图显示字体（用于美化显示内容）
    SendMessage(hwndListView, WM_SETFONT, (WPARAM)hFont, (LPARAM)TRUE);

    return TRUE;
}

//
//  函数: RearrangeWindow(HWND hWnd)
//
//  目标: 根据窗口大小变化，自动调整控件大小
//
RECT RearrangeWindow(HWND hWnd)
{
    SendMessage(hwndStatus, WM_SIZE, 0, 0);   // 底部状态栏紧贴底部

    GetClientRect(hWnd, &rect);
    GetClientRect(hwndTreeView, &rcTree);

    MoveWindow(hwndTreeView,
        rect.left, rect.top,
        rcTree.right + 2, rect.bottom - uStatusHeight,
        TRUE);

    MoveWindow(hwndListView,
        rcTree.right + 5, rect.top,
        rect.right - rcTree.right - 6, rect.bottom - uStatusHeight,
        TRUE);

    return rect;
}

//
//  函数: SlippageWindow(HWND hWnd, WORD wxPos)
//
//  目标: 根据窗口大小变化，自动调整控件大小
//
DWORD SlippageWindow(HWND hWnd, WORD wxPos)
{
    GetClientRect(hWnd, &rect);

    MoveWindow(hwndTreeView,
        rect.left, rect.top,
        wxPos - 2, rect.bottom - uStatusHeight,
        TRUE);

    MoveWindow(hwndListView,
        wxPos + 1, rect.top,
        rect.right - wxPos - 2, rect.bottom - uStatusHeight,
        TRUE);

    return 0;
}

//
//  函数: OnNotify(WPARAM wParam, LPARAM(lParam))
//
//  目标: 判断鼠标是否在树视图单双击
//
BOOL OnNotify(WPARAM wParam, LPARAM lParam)
{
    LPNMHDR lPhr = (LPNMHDR)lParam;
    if (lPhr->hwndFrom == hwndTreeView)
    {
        switch (lPhr->code)
        {
        case NM_CLICK:
             OnClickTree(lPhr);
            break;
        }
    }
    return TRUE;
}





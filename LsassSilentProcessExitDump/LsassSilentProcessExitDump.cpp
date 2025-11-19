#include <Windows.h>
#include <iostream>

typedef NTSTATUS(NTAPI* RtlReportSilentProcessExit_func) (
    _In_     HANDLE         ProcessHandle,
    _In_     NTSTATUS		ExitStatus
);

BOOL EnableDebugPrivilege(BOOL bEnable)
{
    HANDLE hToken = nullptr;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;

    TOKEN_PRIVILEGES tokenPriv;
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return FALSE;

    return TRUE;
}

int main(int argc, char* argv[])
{

    // Must need SeDebugPrivilege
    // In default, Administrator account doesn't enable SeDebugPrivilege
    if (!EnableDebugPrivilege(TRUE))
    {
        std::cout << "ERROR: Failed to enable debug privilege!\n";
        return -1;
    }

    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    RtlReportSilentProcessExit_func RtlReportSilentProcessExit = (RtlReportSilentProcessExit_func)GetProcAddress(hNtdll, "RtlReportSilentProcessExit");

    int pid = atoi(argv[1]);

    DWORD desiredAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;

    HANDLE hProcess = OpenProcess(desiredAccess, FALSE, pid);

    if (hProcess == INVALID_HANDLE_VALUE)
    {
        int lastError = GetLastError();

        std::cout << "ERROR OpenProcess() failed with error: " << lastError << "\n";
        return -1;
    }


    NTSTATUS ntstatus = RtlReportSilentProcessExit(hProcess, 0);

    std::cout << "RtlReportSilentProcessExit() NTSTATUS: " << std::hex << ntstatus << "\n";

    std::cout << "DONE!" << "\n";

    return 0;
}
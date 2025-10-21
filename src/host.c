/*
 * Host Program - Example target for virus infection
 * This program demonstrates normal functionality that would be preserved
 * after virus infection using EPO techniques
 */

#include <windows.h>
#include <stdio.h>

int main() {
    // Original host program functionality
    MessageBoxA(NULL, 
                "This is the original host program\n"
                "MSSV: 23521308-23521761-23521828-23521840", 
                "Host Program", 
                MB_OK | MB_ICONINFORMATION);

    printf("Host program executed successfully\n");
    printf("Original functionality preserved after infection\n");

    return 0;
}

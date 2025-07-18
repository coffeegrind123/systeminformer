#pragma once

#include <Windows.h>
#include <TlHelp32.h>

// Pure AmalgamLoader manual mapping functionality
// No obfuscation, logging, or extra features

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
    HINSTANCE hMod;
} MANUAL_INJECT, * PMANUAL_INJECT;

// Pure manual mapping functions
DWORD WINAPI GetProcessIdByName(const wchar_t* processName);
int WINAPI ManualMapInject(const wchar_t* dllPath, DWORD processId);
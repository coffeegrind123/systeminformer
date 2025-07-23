#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <winnt.h>
#include <psapi.h>
#include <amalgamcore.h>

// Debug configuration - set to 1 to enable logging, 0 to disable completely
#define AMALGAMDEBUG 1

#if AMALGAMDEBUG
#define DEBUG_MARKER(inject, value) ((inject)->hMod = (HINSTANCE)(value))
#else
#define DEBUG_MARKER(inject, value) ((void)0)
#endif

// Types that were provided by phapp.h  
typedef LONG NTSTATUS;
typedef BOOLEAN *PBOOLEAN;

// PE constants that may not be defined in Windows.h
#ifndef IMAGE_DIRECTORY_ENTRY_TLS
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#endif

#ifndef IMAGE_REL_BASED_DIR64
#define IMAGE_REL_BASED_DIR64 10
#endif

// TLS callback typedef
typedef VOID (WINAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, ULONG Reason, PVOID Reserved);

// Ensure PE format constants are defined
#ifndef IMAGE_DIRECTORY_ENTRY_TLS
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#endif

#ifndef IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#endif

// TLS callback type if not defined
#ifndef PIMAGE_TLS_CALLBACK
typedef VOID (WINAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle, ULONG Reason, PVOID Reserved);
#endif

// Simple debug logging implementation
void AmalgamLog(const char* fmt, ...) {
#if AMALGAMDEBUG
    static FILE* logFile = NULL;
    if (!logFile) {
        #ifdef _MSC_VER
        fopen_s(&logFile, "AmalgamCore.log", "a");
        #else
        logFile = fopen("AmalgamCore.log", "a");
        #endif
    }
    if (logFile) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(logFile, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
        
        va_list args;
        va_start(args, fmt);
        vfprintf(logFile, fmt, args);
        va_end(args);
        
        fprintf(logFile, "\n");
        fflush(logFile);
    }
#else
    // Logging disabled - do nothing
    (void)fmt; // Suppress unused parameter warning
#endif
}

// Function declarations that were provided by phapp.h
NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

// Forward declarations
DWORD WINAPI LoadDll(PVOID p);
DWORD WINAPI LoadDllEnd(void);

// ManualGetProcAddress is no longer needed - we use the real fnGetProcAddress from ManualInject structure

// Position-independent shellcode function
DWORD WINAPI LoadDll(PVOID p)
{
    PMANUAL_INJECT ManualInject;
    HMODULE hModule;
    DWORD64 i, Function, count, delta;
    DWORD64* ptr;
    PWORD list;
    PIMAGE_BASE_RELOCATION pIBR;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    PIMAGE_IMPORT_BY_NAME pIBN;
    PDLL_MAIN EntryPoint;

    ManualInject = (PMANUAL_INJECT)p;

    if (!ManualInject) {
        return FALSE;
    }

    // Mark that we entered the function successfully
    DEBUG_MARKER(ManualInject, 0x1234); // Entry marker

    // Handle relocations
    pIBR = ManualInject->BaseRelocation;
    DEBUG_MARKER(ManualInject, 0x1235); // Before delta calculation
    delta = (DWORD64)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);
    DEBUG_MARKER(ManualInject, 0x1236); // After delta calculation

    if (pIBR && delta != 0)
    {
        DEBUG_MARKER(ManualInject, 0x1237); // Starting relocations
        while (pIBR->VirtualAddress)
        {
            if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
            {
                count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                list = (PWORD)(pIBR + 1);

                for (i = 0; i < count; i++)
                {
                    if (list[i])
                    {
                        WORD type = (list[i] >> 12) & 0xF;
                        WORD offset = list[i] & 0xFFF;
                        
                        if (type == IMAGE_REL_BASED_DIR64)
                        {
                            ptr = (DWORD64*)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + offset));
                            *ptr += delta;
                        }
                    }
                }
            }
            pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
        }
    }

    DEBUG_MARKER(ManualInject, 0x1238); // Relocations complete
    
    // Handle imports
    pIID = ManualInject->ImportDirectory;

    if (pIID)
    {
        DEBUG_MARKER(ManualInject, 0x1239); // Starting import processing
        
        // Loop through each DLL that needs to be imported (exact AmalgamLoader approach)
        DEBUG_MARKER(ManualInject, 0x1260); // About to check pIID->Name
        while (pIID->Name)
        {
            DEBUG_MARKER(ManualInject, 0x1261); // Inside while loop, processing DLL
            // Get pointers to the thunk tables (as shown in tutorial)
            DEBUG_MARKER(ManualInject, 0x1262); // About to access OriginalFirstThunk
            DWORD64* pThunk = (DWORD64*)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
            DEBUG_MARKER(ManualInject, 0x1263); // About to access FirstThunk
            DWORD64* pFunc = (DWORD64*)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

            // If OriginalFirstThunk not defined, use FirstThunk (as per tutorial)
            DEBUG_MARKER(ManualInject, 0x1264); // Checking OriginalFirstThunk
            if (!pThunk) { pThunk = pFunc; }

            // Load the required DLL module
            DEBUG_MARKER(ManualInject, 0x1265); // About to access pIID->Name
            char* importName = (char*)((LPBYTE)ManualInject->ImageBase + pIID->Name);
            
            // Validate the import name string before calling LoadLibraryA
            DEBUG_MARKER(ManualInject, 0x1269); // Got import name, checking validity
            if (!importName || (DWORD64)importName < 0x1000) {
                DEBUG_MARKER(ManualInject, 0x126A); // Invalid import name pointer
                return FALSE;
            }
            
            // Try to access first character to test string validity
            DEBUG_MARKER(ManualInject, 0x126B); // About to test string access
            __try {
                volatile char firstChar = importName[0];
                if (firstChar == 0) {
                    DEBUG_MARKER(ManualInject, 0x126C); // Empty import name
                    return FALSE;
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                DEBUG_MARKER(ManualInject, 0x126D); // Failed to access import name string
                return FALSE;
            }
            
            DEBUG_MARKER(ManualInject, 0x1266); // About to call LoadLibraryA
            hModule = ManualInject->fnLoadLibraryA(importName);
            DEBUG_MARKER(ManualInject, 0x1267); // LoadLibraryA completed successfully

            if (!hModule)
            {
                DEBUG_MARKER(ManualInject, 0x404);
                return FALSE;
            }
            
            DEBUG_MARKER(ManualInject, 0x1246); // DLL module resolved, starting function resolution

            // Process each function import in this DLL (like ProcessClient.cpp)
            for (; *pThunk; ++pThunk, ++pFunc)
            {
                
                if (*pThunk & IMAGE_ORDINAL_FLAG64)
                {
                    // Import by ordinal (64-bit) - function imported by number
                    DEBUG_MARKER(ManualInject, 0x1247); // About to call GetProcAddress (ordinal)
                    Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(*pThunk & 0xFFFF));
                    DEBUG_MARKER(ManualInject, 0x1248); // GetProcAddress (ordinal) completed
                    if (!Function)
                    {
                        DEBUG_MARKER(ManualInject, 0x405); // Ordinal import failed
                        return FALSE;
                    }
                    *pFunc = Function; // Update IAT with function address
                }
                else
                {
                    // Import by name (64-bit) - function imported by name
                    DEBUG_MARKER(ManualInject, 0x1249); // About to access import by name structure
                    pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + *pThunk);
                    DEBUG_MARKER(ManualInject, 0x124A); // About to call GetProcAddress (name)
                    Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
                    DEBUG_MARKER(ManualInject, 0x124B); // GetProcAddress (name) completed
                    if (!Function)
                    {
                        DEBUG_MARKER(ManualInject, 0x406); // Name import failed
                        return FALSE;
                    }
                    *pFunc = Function; // Update IAT with function address
                }
            }
            
            DEBUG_MARKER(ManualInject, 0x123F); // Successfully resolved imports

            pIID++;
        }
    }

    DEBUG_MARKER(ManualInject, 0x1250); // About to execute TLS callbacks
    
    // Execute TLS callbacks
    if (ManualInject->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        PIMAGE_TLS_DIRECTORY64 pTLS;
        PIMAGE_TLS_CALLBACK* pCallback;
        
        DEBUG_MARKER(ManualInject, 0x1251); // TLS directory found, processing
        pTLS = (PIMAGE_TLS_DIRECTORY64)((LPBYTE)ManualInject->ImageBase + 
            ManualInject->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        
        if (pTLS && pTLS->AddressOfCallBacks)
        {
            DEBUG_MARKER(ManualInject, 0x1252); // TLS callbacks found, about to call
            pCallback = (PIMAGE_TLS_CALLBACK*)pTLS->AddressOfCallBacks;
            for (; pCallback && *pCallback; ++pCallback)
            {
                DEBUG_MARKER(ManualInject, 0x1253); // About to call TLS callback
                (*pCallback)((LPVOID)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
                DEBUG_MARKER(ManualInject, 0x1254); // TLS callback completed
            }
        }
    }
    
    DEBUG_MARKER(ManualInject, 0x1255); // TLS callbacks completed, about to call DllMain

    // Try to call DLL main with improved error handling 
    // Many DLLs need DllMain called to actually start their functionality
    if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        
        DEBUG_MARKER(ManualInject, 0x1256); // About to calculate DllMain entry point
        EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        
        DEBUG_MARKER(ManualInject, 0x1257); // DllMain entry point calculated, about to call
        __try
        {
            // Call DllMain with DLL_PROCESS_ATTACH like AmalgamLoader
            DEBUG_MARKER(ManualInject, 0x1258); // Inside DllMain call
            BOOL result = EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
            DEBUG_MARKER(ManualInject, 0x1259); // DllMain call completed
            
            // Set status for debugging purposes (like AmalgamLoader)
            ManualInject->hMod = result ? (HINSTANCE)ManualInject->ImageBase : (HINSTANCE)0x407;
            
            return result; // Return actual DllMain result like AmalgamLoader
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            // DLL entry point crashed
            DEBUG_MARKER(ManualInject, 0x408);
            return FALSE; // Return FALSE on crash like AmalgamLoader
        }
    }

    ManualInject->hMod = (HINSTANCE)ManualInject->ImageBase;
    return TRUE;
}

DWORD WINAPI LoadDllEnd()
{
    return 0;
}

DWORD WINAPI GetProcessIdByName(const wchar_t* processName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Fixed: use 0 instead of NULL
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, processName) == 0)
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}

DWORD WINAPI GetProcessIdByNameExcludeSelf(const wchar_t* processName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    DWORD currentPid = GetCurrentProcessId();
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, processName) == 0 && entry.th32ProcessID != currentPid)
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}

int WINAPI ManualMapInject(const wchar_t* dllPath, const wchar_t* processName)
{
    HANDLE hProcess, hThread, hFile;
    PVOID mem1;
    DWORD FileSize, read, i;
    PVOID buffer, image;
    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS pINH;
    MANUAL_INJECT ManualInject;
    BOOLEAN bl;
    DWORD processId;

    AmalgamLog("Manual mapping injection initialized for process: %ws", processName);
    AmalgamLog("DLL path: %ws", dllPath);

    // Get process ID from process name (excluding self to avoid self-injection)
    processId = GetProcessIdByNameExcludeSelf(processName);
    if (processId == 0) {
        AmalgamLog("Failed to find process: %ws (excluding self)", processName);
        return -1;
    }
    AmalgamLog("Found process %ws with PID %d", processName, processId);

    // Enable debug privileges (critical for accessing protected processes)
    NTSTATUS status = RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
    if (status != 0) {
        AmalgamLog("Warning: Failed to enable debug privileges (status: 0x%X)", status);
        AmalgamLog("Continuing anyway - may affect protected process access");
    } else {
        AmalgamLog("Debug privileges enabled successfully");
    }

    // Open process
    AmalgamLog("Opening process with PID %d", processId);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        DWORD error = GetLastError();
        AmalgamLog("Failed to open target process (error: %d)", error);
        return -1;
    }
    AmalgamLog("Process opened successfully");

    // Validate target process is 64-bit
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(hProcess, &isWow64)) {
        DWORD error = GetLastError();
        AmalgamLog("Error checking target architecture (error: %d)", error);
        CloseHandle(hProcess);
        return -1;
    }
    if (isWow64) {
        AmalgamLog("Target process is 32-bit, but this loader is strictly 64-bit only");
        CloseHandle(hProcess);
        return -1;
    }
    AmalgamLog("Target process architecture validated (64-bit)");

    // Load DLL file
    AmalgamLog("Loading DLL file into memory");
    hFile = CreateFile(dllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD error = GetLastError();
        AmalgamLog("Unable to open the DLL (error: %d)", error);
        CloseHandle(hProcess);
        return -1;
    }

    FileSize = GetFileSize(hFile, NULL);
    AmalgamLog("DLL file size: %d bytes", FileSize);
    
    buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        DWORD error = GetLastError();
        AmalgamLog("Unable to allocate memory for DLL data (error: %d)", error);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return -1;
    }

    if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
    {
        DWORD error = GetLastError();
        AmalgamLog("Unable to read the DLL (error: %d)", error);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return -1;
    }
    CloseHandle(hFile);
    AmalgamLog("DLL loaded successfully into buffer");

    // PE validation
    AmalgamLog("Validating PE structure");
    pIDH = (PIMAGE_DOS_HEADER)buffer;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        AmalgamLog("Invalid executable image (DOS signature)");
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE)
    {
        AmalgamLog("Invalid PE header (NT signature)");
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        AmalgamLog("The image is not a DLL");
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    if (pINH->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        AmalgamLog("Invalid DLL architecture: Expected x64, got 0x%x", pINH->FileHeader.Machine);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    AmalgamLog("PE validation successful");

    // Allocate memory in target process
    AmalgamLog("Allocating memory in target process (size: %d bytes)", pINH->OptionalHeader.SizeOfImage);
    image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image)
    {
        DWORD error = GetLastError();
        AmalgamLog("Unable to allocate memory for the DLL (error: %d)", error);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    AmalgamLog("Memory allocated at address: 0x%p", image);

    // Copy PE header
    if (!WriteProcessMemory(hProcess, image, buffer, 0x1000, NULL))
    {
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Copy sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pINH);
    for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
    {
        if (pSectionHeader->PointerToRawData)
        {
            WriteProcessMemory(hProcess, 
                (PVOID)((LPBYTE)image + pSectionHeader->VirtualAddress), 
                (PVOID)((LPBYTE)buffer + pSectionHeader->PointerToRawData), 
                pSectionHeader->SizeOfRawData, NULL);
        }
        pSectionHeader++;
    }

    // Calculate loader size with enhanced safety checks
    DWORD64 loadDllAddr = (DWORD64)LoadDll;
    DWORD64 loadDllEndAddr = (DWORD64)LoadDllEnd;
    DWORD64 loadDllSize;
    
    if (loadDllEndAddr > loadDllAddr) {
        loadDllSize = loadDllEndAddr - loadDllAddr;
    } else {
        loadDllSize = 2048;
        AmalgamLog("Warning: LoadDll function size calculation failed, using fallback size: %llu", loadDllSize);
    }
    
    if (loadDllSize > 0x10000) {
        loadDllSize = 2048;
        AmalgamLog("Warning: LoadDll function size too large, using fallback size: %llu", loadDllSize);
    }
    
    DWORD totalLoaderSize = (DWORD)(sizeof(MANUAL_INJECT) + loadDllSize + 512);
    AmalgamLog("Allocating loader code memory (size: %d bytes)", totalLoaderSize);
    
    mem1 = VirtualAllocEx(hProcess, NULL, totalLoaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem1)
    {
        DWORD error = GetLastError();
        AmalgamLog("Unable to allocate memory for the loader code (error: %d)", error);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    AmalgamLog("Loader code allocated at 0x%p", mem1);

    // Setup ManualInject structure
    AmalgamLog("Setting up ManualInject structure");
    memset(&ManualInject, 0, sizeof(MANUAL_INJECT));
    ManualInject.ImageBase = image;
    ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
    ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    // Get correct function addresses for target process
    HMODULE hKernel32Local = GetModuleHandleA("kernel32.dll");
    HMODULE hKernel32Remote = NULL;
    
    // Find kernel32.dll in target process
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < moduleCount; i++) {
            wchar_t moduleName[MAX_PATH];
            if (GetModuleBaseName(hProcess, hMods[i], moduleName, MAX_PATH)) {
                if (_wcsicmp(moduleName, L"kernel32.dll") == 0) {
                    hKernel32Remote = hMods[i];
                    break;
                }
            }
        }
    }
    
    if (!hKernel32Remote) {
        AmalgamLog("Failed to find kernel32.dll in target process");
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    
    // Calculate function addresses in target process
    DWORD64 kernel32Offset = (DWORD64)hKernel32Remote - (DWORD64)hKernel32Local;
    ManualInject.fnLoadLibraryA = (pLoadLibraryA)((DWORD64)LoadLibraryA + kernel32Offset);
    ManualInject.fnGetProcAddress = (pGetProcAddress)((DWORD64)GetProcAddress + kernel32Offset);
    
    AmalgamLog("Manual inject structure initialized - ImageBase: 0x%p", image);
    AmalgamLog("NtHeaders: 0x%p, BaseRelocation: 0x%p, ImportDirectory: 0x%p", 
               ManualInject.NtHeaders, ManualInject.BaseRelocation, ManualInject.ImportDirectory);
    AmalgamLog("kernel32.dll: Local=0x%p, Remote=0x%p, Offset=0x%llX", 
               hKernel32Local, hKernel32Remote, kernel32Offset);
    AmalgamLog("LoadLibraryA: 0x%p, GetProcAddress: 0x%p", ManualInject.fnLoadLibraryA, ManualInject.fnGetProcAddress);
    AmalgamLog("Original ImageBase from PE: 0x%llX, Target ImageBase: 0x%p", 
               pINH->OptionalHeader.ImageBase, image);

    // Write ManualInject structure
    if (!WriteProcessMemory(hProcess, mem1, &ManualInject, sizeof(MANUAL_INJECT), NULL))
    {
        DWORD error = GetLastError();
        AmalgamLog("Memory write error for structure (error: %d)", error);
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Write LoadDll function
    PVOID functionAddress = (PVOID)((PMANUAL_INJECT)mem1 + 1);
    AmalgamLog("Writing LoadDll function to address: 0x%p (size: %llu bytes)", functionAddress, loadDllSize);
    AmalgamLog("Loader memory layout: Structure at 0x%p, Function at 0x%p", mem1, functionAddress);
    AmalgamLog("Structure size: %zu, Function starts at offset: %zu", sizeof(MANUAL_INJECT), sizeof(MANUAL_INJECT));
    
    if (!WriteProcessMemory(hProcess, functionAddress, LoadDll, (SIZE_T)loadDllSize, NULL))
    {
        DWORD error = GetLastError();
        AmalgamLog("Memory write error for function (error: %d)", error);
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    AmalgamLog("LoadDll function written successfully");

    // Create remote thread
    AmalgamLog("Creating remote thread to execute LoadDll function...");
    AmalgamLog("CreateRemoteThread parameters: Function=0x%p, Parameter=0x%p", functionAddress, mem1);
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)functionAddress, mem1, 0, NULL);
    if (!hThread)
    {
        DWORD error = GetLastError();
        AmalgamLog("Unable to create remote thread (error: %d)", error);
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    AmalgamLog("Remote thread created successfully");

    // Wait for completion with proper error handling
    AmalgamLog("Waiting for remote thread to complete...");
    DWORD waitResult = WaitForSingleObject(hThread, 10000);
    
    if (waitResult == WAIT_TIMEOUT) {
        AmalgamLog("Remote thread timed out after 10 seconds");
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    else if (waitResult == WAIT_FAILED) {
        DWORD error = GetLastError();
        AmalgamLog("Wait for remote thread failed (error: %d)", error);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    
    // Check thread exit code and injection status
    DWORD threadExitCode;
    GetExitCodeThread(hThread, &threadExitCode);
    AmalgamLog("Remote thread completed with exit code: %d", threadExitCode);
    
    // Check for critical system errors that indicate injection failure
    if (threadExitCode == 0xC0000005) {  // STATUS_ACCESS_VIOLATION
        AmalgamLog("ERROR: DLL crashed during initialization (Access Violation)");
        
        // Try to read debug markers to see where it crashed
        MANUAL_INJECT statusCheck;
        if (ReadProcessMemory(hProcess, mem1, &statusCheck, sizeof(statusCheck), NULL)) {
            AmalgamLog("Debug marker at crash: 0x%p", statusCheck.hMod);
            if (statusCheck.hMod == (HINSTANCE)0x1234) {
                AmalgamLog("Crashed after entering LoadDll function");
            } else if (statusCheck.hMod == (HINSTANCE)0x1235) {
                AmalgamLog("Crashed during delta calculation");
            } else if (statusCheck.hMod == (HINSTANCE)0x1236) {
                AmalgamLog("Crashed after delta calculation, before relocations");
            } else if (statusCheck.hMod == (HINSTANCE)0x1237) {
                AmalgamLog("Crashed during relocation processing");
            } else if (statusCheck.hMod == (HINSTANCE)0x1238) {
                AmalgamLog("Crashed after relocations, before import processing");
            } else if (statusCheck.hMod == (HINSTANCE)0x1239) {
                AmalgamLog("Crashed during import directory access");
            } else if ((DWORD64)statusCheck.hMod >= 0x1260 && (DWORD64)statusCheck.hMod <= 0x126D) {
                AmalgamLog("Crashed during import processing - marker: 0x%llX", (DWORD64)statusCheck.hMod);
                if (statusCheck.hMod == (HINSTANCE)0x1269) {
                    AmalgamLog("Crash: Got import name, checking validity");
                } else if (statusCheck.hMod == (HINSTANCE)0x126A) {
                    AmalgamLog("Crash: Invalid import name pointer");
                } else if (statusCheck.hMod == (HINSTANCE)0x126B) {
                    AmalgamLog("Crash: About to test string access");
                } else if (statusCheck.hMod == (HINSTANCE)0x126C) {
                    AmalgamLog("Crash: Empty import name");
                } else if (statusCheck.hMod == (HINSTANCE)0x126D) {
                    AmalgamLog("Crash: Failed to access import name string");
                } else if (statusCheck.hMod == (HINSTANCE)0x1266) {
                    AmalgamLog("Crash: About to call LoadLibraryA (function pointer issue)");
                } else if (statusCheck.hMod == (HINSTANCE)0x1268) {
                    AmalgamLog("Crash: LoadLibraryA crashed");
                }
            } else if ((DWORD64)statusCheck.hMod >= 0x1250 && (DWORD64)statusCheck.hMod <= 0x1259) {
                AmalgamLog("Crashed during TLS/DllMain processing - marker: 0x%llX", (DWORD64)statusCheck.hMod);
            } else {
                AmalgamLog("Crashed with unknown debug marker: 0x%p", statusCheck.hMod);
            }
        } else {
            AmalgamLog("Could not read debug markers from crashed process");
        }
        
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    if (threadExitCode == 0xC000001D) {  // STATUS_ILLEGAL_INSTRUCTION
        AmalgamLog("ERROR: DLL crashed during initialization (Illegal Instruction)");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    
    // Read back the status from the injected structure
    MANUAL_INJECT statusCheck;
    if (ReadProcessMemory(hProcess, mem1, &statusCheck, sizeof(statusCheck), NULL)) {
        if (statusCheck.hMod == (HINSTANCE)0x404) {
            AmalgamLog("LoadDll function failed - module loading failed");
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
            VirtualFree(buffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }
        else if (statusCheck.hMod == (HINSTANCE)0x405) {
            AmalgamLog("LoadDll function failed - ordinal import failed");
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
            VirtualFree(buffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }
        else if (statusCheck.hMod == (HINSTANCE)0x406) {
            AmalgamLog("LoadDll function failed - name import failed");
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
            VirtualFree(buffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }
        else if (statusCheck.hMod == (HINSTANCE)0x407) {
            AmalgamLog("LoadDll function failed - DLL entry point returned FALSE");
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
            VirtualFree(buffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }
        else if (statusCheck.hMod == (HINSTANCE)0x408) {
            AmalgamLog("LoadDll function failed - DLL entry point crashed");
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
            VirtualFree(buffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1234) {
            AmalgamLog("LoadDll function entered but crashed before delta calculation");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1235) {
            AmalgamLog("LoadDll function crashed during delta calculation");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1236) {
            AmalgamLog("LoadDll function crashed after delta calculation, before relocations");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1237) {
            AmalgamLog("LoadDll function crashed during relocation processing");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1238) {
            AmalgamLog("LoadDll function crashed after relocations, before import processing");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1239) {
            AmalgamLog("LoadDll function crashed during import directory access");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123A) {
            AmalgamLog("LoadDll function crashed during DLL name string access");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123B) {
            AmalgamLog("LoadDll function crashed after LoadLibraryA, during GetProcAddress");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123C) {
            AmalgamLog("LoadDll function failed - invalid import name pointer");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123D) {
            AmalgamLog("LoadDll function crashed while calculating importName pointer");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123E) {
            AmalgamLog("LoadDll function crashed during string validation (after pointer calc)");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123F) {
            AmalgamLog("LoadDll function using dummy base for unknown DLL import");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1240) {
            AmalgamLog("LoadDll function using placeholder function resolution (GetProcAddress bypass)");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1241) {
            AmalgamLog("LoadDll function crashed during import directory access");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1242) {
            AmalgamLog("LoadDll function found empty DLL name string");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1243) {
            AmalgamLog("LoadDll function crashed after successful string access");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1244) {
            AmalgamLog("LoadDll function failed - import directory pointer out of bounds");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1245) {
            AmalgamLog("LoadDll function crashed during DLL module resolution");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1246) {
            AmalgamLog("LoadDll function crashed during function resolution");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1247) {
            AmalgamLog("LoadDll function crashed in ManualGetProcAddress (ordinal import)");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1248) {
            AmalgamLog("LoadDll function crashed after ManualGetProcAddress (ordinal) completed");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1249) {
            AmalgamLog("LoadDll function crashed accessing import by name structure");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x124A) {
            AmalgamLog("LoadDll function crashed in ManualGetProcAddress (name import)");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x124B) {
            AmalgamLog("LoadDll function crashed after ManualGetProcAddress (name) completed");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x124C) {
            AmalgamLog("LoadDll function crashed during ManualGetProcAddress call setup");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x124D) {
            AmalgamLog("LoadDll function crashed after accessing import by name structure");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x124E) {
            AmalgamLog("LoadDll function failed - invalid import by name pointer");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1250) {
            AmalgamLog("LoadDll function crashed before TLS callback processing");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1251) {
            AmalgamLog("LoadDll function crashed during TLS directory processing");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1252) {
            AmalgamLog("LoadDll function crashed before calling TLS callbacks");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1253) {
            AmalgamLog("LoadDll function crashed during TLS callback execution");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1254) {
            AmalgamLog("LoadDll function crashed after TLS callback completed");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1255) {
            AmalgamLog("LoadDll function crashed after TLS callbacks, before DllMain");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1256) {
            AmalgamLog("LoadDll function crashed while calculating DllMain entry point");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1257) {
            AmalgamLog("LoadDll function crashed right before calling DllMain");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1258) {
            AmalgamLog("LoadDll function crashed during DllMain execution");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x1259) {
            AmalgamLog("LoadDll function crashed after DllMain completed");
        }
        else if (statusCheck.hMod == statusCheck.ImageBase) {
            AmalgamLog("LoadDll function completed successfully");
        }
        else {
            AmalgamLog("LoadDll function status unknown (hMod: 0x%p, exit code: %ld)", statusCheck.hMod, threadExitCode);
        }
    }
    
    CloseHandle(hThread);
    
    // Give DLL time to initialize before cleanup
    AmalgamLog("Giving DLL time to initialize (2 second delay)");
    Sleep(2000);

    // Only cleanup loader memory, keep DLL image
    VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    AmalgamLog("Manual mapping injection completed successfully");
    return 0;
}
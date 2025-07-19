#include <phapp.h>
#include <amalgamcore.h>

// RtlAdjustPrivilege is already declared in phlib headers

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
    ManualInject->hMod = (HINSTANCE)0x1234; // Entry marker

    // Handle relocations
    pIBR = ManualInject->BaseRelocation;
    ManualInject->hMod = (HINSTANCE)0x1235; // Before delta calculation
    delta = (DWORD64)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);
    ManualInject->hMod = (HINSTANCE)0x1236; // After delta calculation

    if (pIBR && delta != 0)
    {
        ManualInject->hMod = (HINSTANCE)0x1237; // Starting relocations
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

    ManualInject->hMod = (HINSTANCE)0x1238; // Relocations complete
    
    // Handle imports
    pIID = ManualInject->ImportDirectory;

    if (pIID)
    {
        ManualInject->hMod = (HINSTANCE)0x1239; // Starting import processing
        while (pIID->Name)
        {
            DWORD64* pThunk = (DWORD64*)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
            DWORD64* pFunc = (DWORD64*)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

            if (!pThunk) { pThunk = pFunc; }

            char* importName = (char*)((LPBYTE)ManualInject->ImageBase + pIID->Name);
            
            // Simple validation that the string is accessible
            ManualInject->hMod = (HINSTANCE)0x123A; // Before LoadLibraryA call
            
            // Try to access the first few characters to validate string accessibility
            if (importName[0] == 0 || importName[1] == 0) {
                ManualInject->hMod = (HINSTANCE)0x123C; // String validation failed
                return FALSE;
            }
            
            hModule = ManualInject->fnLoadLibraryA(importName);
            ManualInject->hMod = (HINSTANCE)0x123B; // After LoadLibraryA call

            if (!hModule)
            {
                ManualInject->hMod = (HINSTANCE)0x404;
                return FALSE;
            }

            for (; *pThunk; ++pThunk, ++pFunc)
            {
                if (*pThunk & IMAGE_ORDINAL_FLAG64)
                {
                    Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(*pThunk & 0xFFFF));
                    if (!Function)
                    {
                        ManualInject->hMod = (HINSTANCE)0x405;
                        return FALSE;
                    }
                    *pFunc = Function;
                }
                else
                {
                    pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + *pThunk);
                    Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
                    if (!Function)
                    {
                        ManualInject->hMod = (HINSTANCE)0x406;
                        return FALSE;
                    }
                    *pFunc = Function;
                }
            }

            pIID++;
        }
    }

    // Execute TLS callbacks
    if (ManualInject->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        PIMAGE_TLS_DIRECTORY64 pTLS = (PIMAGE_TLS_DIRECTORY64)((LPBYTE)ManualInject->ImageBase + 
            ManualInject->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        
        if (pTLS && pTLS->AddressOfCallBacks)
        {
            PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)pTLS->AddressOfCallBacks;
            for (; pCallback && *pCallback; ++pCallback)
            {
                (*pCallback)((LPVOID)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
            }
        }
    }

    // Call DLL main
    if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        
        __try
        {
            BOOL result = EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
            ManualInject->hMod = result ? (HINSTANCE)ManualInject->ImageBase : (HINSTANCE)0x407;
            return result;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            ManualInject->hMod = (HINSTANCE)0x408;
            return FALSE;
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

int WINAPI ManualMapInject(const wchar_t* dllPath, DWORD processId)
{
    HANDLE hProcess, hThread, hFile;
    PVOID mem1;
    DWORD FileSize, read, i;
    PVOID buffer, image;
    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS pINH;
    MANUAL_INJECT ManualInject;
    BOOLEAN bl;

    AmalgamLog("Manual mapping injection initialized for PID %d", processId);
    AmalgamLog("DLL path: %ws", dllPath);

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
    // Ensure function pointers are valid in target process
    // kernel32.dll is typically loaded at the same base address across processes
    HMODULE hKernel32Local = GetModuleHandleA("kernel32.dll");
    if (!hKernel32Local) {
        AmalgamLog("Failed to get local kernel32.dll handle");
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    
    ManualInject.fnLoadLibraryA = (pLoadLibraryA)GetProcAddress(hKernel32Local, "LoadLibraryA");
    ManualInject.fnGetProcAddress = (pGetProcAddress)GetProcAddress(hKernel32Local, "GetProcAddress");
    
    if (!ManualInject.fnLoadLibraryA || !ManualInject.fnGetProcAddress) {
        AmalgamLog("Failed to resolve kernel32 function addresses");
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    
    AmalgamLog("Manual inject structure initialized - ImageBase: 0x%p", image);
    AmalgamLog("NtHeaders: 0x%p, BaseRelocation: 0x%p, ImportDirectory: 0x%p", 
               ManualInject.NtHeaders, ManualInject.BaseRelocation, ManualInject.ImportDirectory);
    AmalgamLog("LoadLibraryA: 0x%p, GetProcAddress: 0x%p", ManualInject.fnLoadLibraryA, ManualInject.fnGetProcAddress);
    AmalgamLog("kernel32.dll base: 0x%p", hKernel32Local);
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
            AmalgamLog("LoadDll function crashed during LoadLibraryA call");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123B) {
            AmalgamLog("LoadDll function crashed after LoadLibraryA, during GetProcAddress");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123C) {
            AmalgamLog("LoadDll function failed - import DLL name string validation failed");
        }
        else if (statusCheck.hMod == statusCheck.ImageBase) {
            AmalgamLog("LoadDll function completed successfully");
        }
        else {
            AmalgamLog("LoadDll function status unknown (hMod: 0x%p)", statusCheck.hMod);
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
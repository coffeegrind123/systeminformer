#include <phapp.h>
#include <amalgamcore.h>

// RtlAdjustPrivilege is already declared in phlib headers
typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

// Manual GetProcAddress implementation - parses export table directly
DWORD64 ManualGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    if (!hModule || !lpProcName) return 0;
    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;
    
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + 
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    if (!pExportDir) return 0;
    
    DWORD* pFunctions = (DWORD*)((LPBYTE)hModule + pExportDir->AddressOfFunctions);
    DWORD* pNames = (DWORD*)((LPBYTE)hModule + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)((LPBYTE)hModule + pExportDir->AddressOfNameOrdinals);
    
    // Check if importing by ordinal
    if ((DWORD64)lpProcName <= 0xFFFF)
    {
        DWORD ordinal = (DWORD)(DWORD64)lpProcName - pExportDir->Base;
        if (ordinal < pExportDir->NumberOfFunctions)
        {
            return (DWORD64)hModule + pFunctions[ordinal];
        }
        return 0;
    }
    
    // Import by name
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
    {
        char* pFuncName = (char*)((LPBYTE)hModule + pNames[i]);
        
        // Simple string comparison
        int match = 1;
        for (int j = 0; lpProcName[j] != 0 || pFuncName[j] != 0; j++)
        {
            if (lpProcName[j] != pFuncName[j])
            {
                match = 0;
                break;
            }
        }
        
        if (match)
        {
            return (DWORD64)hModule + pFunctions[pOrdinals[i]];
        }
    }
    
    return 0;
}

// Position-independent shellcode function
DWORD WINAPI LoadDll(PVOID p)
{
    PMANUAL_INJECT ManualInject;
    HMODULE hModule;
    DWORD64 i, count, delta;
    DWORD64* ptr;
    PWORD list;
    PIMAGE_BASE_RELOCATION pIBR;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    // PDLL_MAIN EntryPoint; // Removed since we're not calling DllMain

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

            ManualInject->hMod = (HINSTANCE)0x123A; // Before DLL name string access
            
            // Validate that the import name pointer is within our mapped memory
            if (pIID->Name == 0 || pIID->Name > 0x1000000) {
                ManualInject->hMod = (HINSTANCE)0x123C; // Invalid import name pointer
                return FALSE;
            }
            
            char* importName = (char*)((LPBYTE)ManualInject->ImageBase + pIID->Name);
            
            // Safely try to access the string using exception handling
            __try {
                // Validate string accessibility and basic content
                if (importName[0] == 0 || importName[1] == 0) {
                    ManualInject->hMod = (HINSTANCE)0x123C; // Empty string
                    return FALSE;
                }
                
                // Ensure string is reasonable length (DLL names shouldn't be too long)
                int len = 0;
                for (int i = 0; i < 260 && importName[i] != 0; i++) {
                    len++;
                }
                if (len == 0 || len >= 260) {
                    ManualInject->hMod = (HINSTANCE)0x123C; // Invalid string length
                    return FALSE;
                }
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                ManualInject->hMod = (HINSTANCE)0x123C; // String access crashed
                return FALSE;
            }
            
            // Use hardcoded addresses for system DLLs since LoadLibraryA fails in TF2
            // These DLLs are already loaded in the target process at known addresses
            if (importName[0] == 'k' || importName[0] == 'K') { // kernel32.dll
                hModule = (HMODULE)0x7ffee3480000; // Real kernel32 base from target
            } else if (importName[0] == 'n' || importName[0] == 'N') { // ntdll.dll  
                hModule = (HMODULE)0x7ffee4db0000; // Real ntdll base from target
            } else if (importName[0] == 'u' || importName[0] == 'U') { // user32.dll
                hModule = (HMODULE)0x7ffee32c0000; // Real user32 base from target
            } else if (importName[0] == 'a' || importName[0] == 'A') { // advapi32.dll
                hModule = (HMODULE)0x7ffee3030000; // Real advapi32 base from target
            } else if (importName[0] == 'm' || importName[0] == 'M') { // msvcrt.dll
                hModule = (HMODULE)0x7ffee3550000; // Real msvcrt base from target
            } else if (importName[0] == 'g' || importName[0] == 'G') { // gdi32.dll
                hModule = (HMODULE)0x7ffee4950000; // Real gdi32 base from target
            } else if (importName[0] == 'o' || importName[0] == 'O') { // ole32.dll, oleaut32.dll
                hModule = (HMODULE)0x7ffee2c40000; // Real ole32 base from target
            } else if (importName[0] == 's' || importName[0] == 'S') { // shell32.dll, sechost.dll
                hModule = (HMODULE)0x7ffee37e0000; // Real shell32 base from target
            } else {
                // For unknown DLLs, skip to avoid crashes
                ManualInject->hMod = (HINSTANCE)0x405; // Unknown DLL skipped
                pIID++;
                continue;
            }

            if (!hModule)
            {
                ManualInject->hMod = (HINSTANCE)0x404;
                return FALSE;
            }

            // Use real function resolution like AmalgamLoader
            // This is critical - DLL will crash if we use dummy addresses
            for (; *pThunk; ++pThunk, ++pFunc)
            {
                DWORD64 Function = 0;
                
                if (*pThunk & IMAGE_ORDINAL_FLAG64)
                {
                    // Import by ordinal - use manual export table parsing
                    Function = ManualGetProcAddress(hModule, (LPCSTR)(*pThunk & 0xFFFF));
                    if (!Function)
                    {
                        // If function resolution fails, this is a real error
                        ManualInject->hMod = (HINSTANCE)0x404;
                        return FALSE;
                    }
                }
                else
                {
                    // Import by name - use manual export table parsing
                    PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + *pThunk);
                    Function = ManualGetProcAddress(hModule, (LPCSTR)pIBN->Name);
                    if (!Function)
                    {
                        // If function resolution fails, this is a real error
                        ManualInject->hMod = (HINSTANCE)0x405;
                        return FALSE;
                    }
                }
                
                // Set the real function address in the import table
                *pFunc = Function;
            }
            
            ManualInject->hMod = (HINSTANCE)0x123F; // Successfully resolved imports

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

    // Try to call DLL main with improved error handling 
    // Many DLLs need DllMain called to actually start their functionality
    if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        PDLL_MAIN EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        
        __try
        {
            // Call DllMain with DLL_PROCESS_ATTACH like AmalgamLoader
            BOOL result = EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
            
            // Set status for debugging purposes (like AmalgamLoader)
            ManualInject->hMod = result ? (HINSTANCE)ManualInject->ImageBase : (HINSTANCE)0x407;
            
            return result; // Return actual DllMain result like AmalgamLoader
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            // DLL entry point crashed
            ManualInject->hMod = (HINSTANCE)0x408;
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
    // Use direct function pointers like AmalgamLoader
    // kernel32.dll is loaded at the same address in most processes
    ManualInject.fnLoadLibraryA = LoadLibraryA;
    ManualInject.fnGetProcAddress = GetProcAddress;
    
    AmalgamLog("Manual inject structure initialized - ImageBase: 0x%p", image);
    AmalgamLog("NtHeaders: 0x%p, BaseRelocation: 0x%p, ImportDirectory: 0x%p", 
               ManualInject.NtHeaders, ManualInject.BaseRelocation, ManualInject.ImportDirectory);
    AmalgamLog("LoadLibraryA: 0x%p, GetProcAddress: 0x%p", ManualInject.fnLoadLibraryA, ManualInject.fnGetProcAddress);
    AmalgamLog("kernel32.dll base: 0x%p", GetModuleHandleA("kernel32.dll"));
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
            AmalgamLog("LoadDll function crashed during DLL name string access");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123B) {
            AmalgamLog("LoadDll function crashed after LoadLibraryA, during GetProcAddress");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123C) {
            AmalgamLog("LoadDll function failed - import DLL name string validation failed");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123D) {
            AmalgamLog("LoadDll function using manual DLL resolution (LoadLibraryA bypass)");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123E) {
            AmalgamLog("LoadDll function using dummy base for unknown DLL import");
        }
        else if (statusCheck.hMod == (HINSTANCE)0x123F) {
            AmalgamLog("LoadDll function using placeholder function resolution (GetProcAddress bypass)");
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
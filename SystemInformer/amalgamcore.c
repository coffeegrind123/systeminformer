#include <amalgamcore.h>

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

    // Handle relocations
    pIBR = ManualInject->BaseRelocation;
    delta = (DWORD64)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);

    if (pIBR && delta != 0)
    {
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

    // Handle imports
    pIID = ManualInject->ImportDirectory;

    if (pIID)
    {
        while (pIID->Name)
        {
            DWORD64* pThunk = (DWORD64*)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
            DWORD64* pFunc = (DWORD64*)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

            if (!pThunk) { pThunk = pFunc; }

            char* importName = (char*)((LPBYTE)ManualInject->ImageBase + pIID->Name);
            hModule = ManualInject->fnLoadLibraryA(importName);

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

    // Open process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
        return -1;

    // Validate target process is 64-bit
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(hProcess, &isWow64)) {
        CloseHandle(hProcess);
        return -1;
    }
    if (isWow64) {
        // Target is 32-bit but we're 64-bit loader
        CloseHandle(hProcess);
        return -1;
    }

    // Load DLL file
    hFile = CreateFile(dllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hProcess);
        return -1;
    }

    FileSize = GetFileSize(hFile, NULL);
    buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return -1;
    }

    if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return -1;
    }
    CloseHandle(hFile);

    // PE validation
    pIDH = (PIMAGE_DOS_HEADER)buffer;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    if (pINH->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Allocate memory in target process
    image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

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

    // Calculate loader size
    DWORD64 loadDllSize = (DWORD64)LoadDllEnd - (DWORD64)LoadDll;
    if (loadDllSize <= 0 || loadDllSize > 0x10000)
        loadDllSize = 2048;
    
    DWORD totalLoaderSize = (DWORD)(sizeof(MANUAL_INJECT) + loadDllSize + 512);
    
    mem1 = VirtualAllocEx(hProcess, NULL, totalLoaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem1)
    {
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Setup ManualInject structure
    memset(&ManualInject, 0, sizeof(MANUAL_INJECT));
    ManualInject.ImageBase = image;
    ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
    ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ManualInject.fnLoadLibraryA = LoadLibraryA;
    ManualInject.fnGetProcAddress = GetProcAddress;

    // Write ManualInject structure
    if (!WriteProcessMemory(hProcess, mem1, &ManualInject, sizeof(MANUAL_INJECT), NULL))
    {
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Write LoadDll function
    PVOID functionAddress = (PVOID)((PMANUAL_INJECT)mem1 + 1);
    if (!WriteProcessMemory(hProcess, functionAddress, LoadDll, (SIZE_T)loadDllSize, NULL))
    {
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Create remote thread
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)functionAddress, mem1, 0, NULL);
    if (!hThread)
    {
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Wait for completion with proper error handling
    DWORD waitResult = WaitForSingleObject(hThread, 10000);
    
    if (waitResult == WAIT_TIMEOUT) {
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
    else if (waitResult == WAIT_FAILED) {
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
    
    // Read back the status from the injected structure
    MANUAL_INJECT statusCheck;
    if (ReadProcessMemory(hProcess, mem1, &statusCheck, sizeof(statusCheck), NULL)) {
        if (statusCheck.hMod == (HINSTANCE)0x404 ||
            statusCheck.hMod == (HINSTANCE)0x405 ||
            statusCheck.hMod == (HINSTANCE)0x406 ||
            statusCheck.hMod == (HINSTANCE)0x407 ||
            statusCheck.hMod == (HINSTANCE)0x408) {
            // Injection failed
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
            VirtualFree(buffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }
    }
    
    CloseHandle(hThread);
    
    // Give DLL time to initialize before cleanup
    Sleep(2000);

    // Only cleanup loader memory, keep DLL image
    VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
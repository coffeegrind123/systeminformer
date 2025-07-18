/*
 * Copyright (c) 2022 Winsider Seminars & Solutions, Inc.  All rights reserved.
 *
 * This file is part of System Informer.
 *
 * Authors:
 *
 *     wj32    2009-2016
 *     dmex    2017-2024
 *
 */

#include <ph.h>
#include <apiimport.h>
#include <kphuser.h>
#include <lsasup.h>
#include <mapldr.h>

/**
 * Opens a thread.
 *
 * \param ThreadHandle A variable which receives a handle to the thread.
 * \param DesiredAccess The desired access to the thread.
 * \param ThreadId The ID of the thread.
 */
NTSTATUS PhOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ThreadId
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    KPH_LEVEL level;

    clientId.UniqueProcess = NULL;
    clientId.UniqueThread = ThreadId;

    level = KsiLevel();

    if ((level >= KphLevelMed) && (DesiredAccess & KPH_THREAD_READ_ACCESS) == DesiredAccess)
    {
        status = KphOpenThread(
            ThreadHandle,
            DesiredAccess,
            &clientId
            );
    }
    else
    {
        InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
        status = NtOpenThread(
            ThreadHandle,
            DesiredAccess,
            &objectAttributes,
            &clientId
            );

        if (status == STATUS_ACCESS_DENIED && (level == KphLevelMax))
        {
            status = KphOpenThread(
                ThreadHandle,
                DesiredAccess,
                &clientId
                );
        }
    }

    return status;
}

NTSTATUS PhOpenThreadClientId(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCLIENT_ID ClientId
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    KPH_LEVEL level;

    level = KsiLevel();

    if ((level >= KphLevelMed) && (DesiredAccess & KPH_THREAD_READ_ACCESS) == DesiredAccess)
    {
        status = KphOpenThread(
            ThreadHandle,
            DesiredAccess,
            ClientId
            );
    }
    else
    {
        InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
        status = NtOpenThread(
            ThreadHandle,
            DesiredAccess,
            &objectAttributes,
            ClientId
            );

        if (status == STATUS_ACCESS_DENIED && (level == KphLevelMax))
        {
            status = KphOpenThread(
                ThreadHandle,
                DesiredAccess,
                ClientId
                );
        }
    }

    return status;
}

/** Limited API for untrusted/external code. */
NTSTATUS PhOpenThreadPublic(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE ThreadId
    )
{
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;

    clientId.UniqueProcess = NULL;
    clientId.UniqueThread = ThreadId;

    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

    return NtOpenThread(
        ThreadHandle,
        DesiredAccess,
        &objectAttributes,
        &clientId
        );
}

NTSTATUS PhOpenThreadProcess(
    _In_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInfo;
    KPH_LEVEL level;

    level = KsiLevel();

    if (level == KphLevelMax || (level >= KphLevelMed && FlagOn(DesiredAccess, KPH_PROCESS_READ_ACCESS) == DesiredAccess))
    {
        status = KphOpenThreadProcess(
            ThreadHandle,
            DesiredAccess,
            ProcessHandle
            );

        if (NT_SUCCESS(status))
            return status;
    }

    status = PhGetThreadBasicInformation(
        ThreadHandle,
        &basicInfo
        );

    if (!NT_SUCCESS(status))
        return status;

    status = PhOpenProcessClientId(
        ProcessHandle,
        DesiredAccess,
        &basicInfo.ClientId
        );

    return status;
}

NTSTATUS PhTerminateThread(
    _In_ HANDLE ThreadHandle,
    _In_ NTSTATUS ExitStatus
    )
{
    NTSTATUS status;

    status = NtTerminateThread(
        ThreadHandle,
        ExitStatus
        );

    return status;
}

/*
 * Retrieves the context of a thread.
 *
 * \param ThreadHandle The handle to the thread.
 * \param ThreadContext A pointer to the CONTEXT structure that receives the thread context.
 *
 * \return The status of the operation.
 */
NTSTATUS PhGetContextThread(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT ThreadContext
    )
{
    NTSTATUS status;

    status = NtGetContextThread(
        ThreadHandle,
        ThreadContext
        );

    return status;
}

NTSTATUS PhGetThreadTebInformationAtomic(
    _In_ HANDLE ThreadHandle,
    _Inout_bytecount_(BytesToRead) PVOID TebInformation,
    _In_ ULONG TebOffset,
    _In_ ULONG BytesToRead
    )
{
    NTSTATUS status;
    THREAD_TEB_INFORMATION threadInfo;
    ULONG returnLength;

    threadInfo.TebInformation = TebInformation;
    threadInfo.TebOffset = TebOffset; // FIELD_OFFSET(TEB, Value);
    threadInfo.BytesToRead = BytesToRead; // RTL_FIELD_SIZE(TEB, Value);

    status = NtQueryInformationThread(
        ThreadHandle,
        ThreadTebInformationAtomic,
        &threadInfo,
        sizeof(THREAD_TEB_INFORMATION),
        &returnLength
        );

    return status;
}

NTSTATUS PhGetThreadName(
    _In_ HANDLE ThreadHandle,
    _Out_ PPH_STRING *ThreadName
    )
{
    NTSTATUS status;
    PTHREAD_NAME_INFORMATION buffer;
    ULONG bufferSize;
    ULONG returnLength;

    if (WindowsVersion < WINDOWS_10)
        return STATUS_NOT_SUPPORTED;

    bufferSize = 0x100;
    buffer = PhAllocate(bufferSize);

    status = NtQueryInformationThread(
        ThreadHandle,
        ThreadNameInformation,
        buffer,
        bufferSize,
        &returnLength
        );

    if (status == STATUS_BUFFER_OVERFLOW)
    {
        PhFree(buffer);
        bufferSize = returnLength;
        buffer = PhAllocate(bufferSize);

        status = NtQueryInformationThread(
            ThreadHandle,
            ThreadNameInformation,
            buffer,
            bufferSize,
            &returnLength
            );
    }

    if (NT_SUCCESS(status))
    {
        // Note: Some threads have UNICODE_NULL as their name. (dmex)
        if (RtlIsNullOrEmptyUnicodeString(&buffer->ThreadName))
        {
            PhFree(buffer);
            return STATUS_UNSUCCESSFUL;
        }

        *ThreadName = PhCreateStringFromUnicodeString(&buffer->ThreadName);
    }

    PhFree(buffer);

    return status;
}

NTSTATUS PhSetThreadName(
    _In_ HANDLE ThreadHandle,
    _In_ PCWSTR ThreadName
    )
{
    NTSTATUS status;
    THREAD_NAME_INFORMATION threadNameInfo;

    if (WindowsVersion < WINDOWS_10)
        return STATUS_NOT_SUPPORTED;

    memset(&threadNameInfo, 0, sizeof(THREAD_NAME_INFORMATION));

    status = RtlInitUnicodeStringEx(
        &threadNameInfo.ThreadName,
        ThreadName
        );

    if (!NT_SUCCESS(status))
        return status;

    status = NtSetInformationThread(
        ThreadHandle,
        ThreadNameInformation,
        &threadNameInfo,
        sizeof(THREAD_NAME_INFORMATION)
        );

    return status;
}

/**
 * Sets a thread's affinity mask.
 *
 * \param ThreadHandle A handle to a thread. The handle must have THREAD_SET_LIMITED_INFORMATION
 * access.
 * \param AffinityMask The new affinity mask.
 */
NTSTATUS PhSetThreadAffinityMask(
    _In_ HANDLE ThreadHandle,
    _In_ KAFFINITY AffinityMask
    )
{
    NTSTATUS status;

    status = NtSetInformationThread(
        ThreadHandle,
        ThreadAffinityMask,
        &AffinityMask,
        sizeof(KAFFINITY)
        );

    if ((status == STATUS_ACCESS_DENIED) && (KsiLevel() == KphLevelMax))
    {
        status = KphSetInformationThread(
            ThreadHandle,
            KphThreadAffinityMask,
            &AffinityMask,
            sizeof(KAFFINITY)
            );
    }

    return status;
}

NTSTATUS PhSetThreadBasePriorityClientId(
    _In_ CLIENT_ID ClientId,
    _In_ KPRIORITY Increment
    )
{
    NTSTATUS status;
    SYSTEM_THREAD_CID_PRIORITY_INFORMATION threadInfo;

    threadInfo.ClientId = ClientId;
    threadInfo.Priority = Increment;

    status = NtSetSystemInformation(
        SystemThreadPriorityClientIdInformation,
        &threadInfo,
        sizeof(SYSTEM_THREAD_CID_PRIORITY_INFORMATION)
        );

    if (status == STATUS_PENDING)
        status = STATUS_SUCCESS;

    return status;
}

NTSTATUS PhSetThreadBasePriority(
    _In_ HANDLE ThreadHandle,
    _In_ KPRIORITY Increment
    )
{
    NTSTATUS status;

    status = NtSetInformationThread(
        ThreadHandle,
        ThreadBasePriority,
        &Increment,
        sizeof(KPRIORITY)
        );

    if ((status == STATUS_ACCESS_DENIED) && (KsiLevel() == KphLevelMax))
    {
        status = KphSetInformationThread(
            ThreadHandle,
            KphThreadBasePriority,
            &Increment,
            sizeof(KPRIORITY)
            );
    }

    return status;
}

/**
 * Sets a thread's I/O priority.
 *
 * \param ThreadHandle A handle to a thread. The handle must have THREAD_SET_LIMITED_INFORMATION
 * access.
 * \param IoPriority The new I/O priority.
 */
NTSTATUS PhSetThreadIoPriority(
    _In_ HANDLE ThreadHandle,
    _In_ IO_PRIORITY_HINT IoPriority
    )
{
    NTSTATUS status;

    status = NtSetInformationThread(
        ThreadHandle,
        ThreadIoPriority,
        &IoPriority,
        sizeof(IO_PRIORITY_HINT)
        );

    if ((status == STATUS_ACCESS_DENIED) && (KsiLevel() == KphLevelMax))
    {
        status = KphSetInformationThread(
            ThreadHandle,
            KphThreadIoPriority,
            &IoPriority,
            sizeof(IO_PRIORITY_HINT)
            );
    }

    return status;
}

NTSTATUS PhSetThreadPagePriority(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG PagePriority
    )
{
    NTSTATUS status;
    PAGE_PRIORITY_INFORMATION pagePriorityInfo;

    pagePriorityInfo.PagePriority = PagePriority;

    status = NtSetInformationThread(
        ThreadHandle,
        ThreadPagePriority,
        &pagePriorityInfo,
        sizeof(PAGE_PRIORITY_INFORMATION)
        );

    if ((status == STATUS_ACCESS_DENIED) && (KsiLevel() == KphLevelMax))
    {
        status = KphSetInformationThread(
            ThreadHandle,
            KphThreadPagePriority,
            &pagePriorityInfo,
            sizeof(PAGE_PRIORITY_INFORMATION)
            );
    }

    return status;
}

NTSTATUS PhSetThreadPriorityBoost(
    _In_ HANDLE ThreadHandle,
    _In_ BOOLEAN DisablePriorityBoost
    )
{
    NTSTATUS status;
    ULONG priorityBoost;

    priorityBoost = DisablePriorityBoost ? 1 : 0;

    status = NtSetInformationThread(
        ThreadHandle,
        ThreadPriorityBoost,
        &priorityBoost,
        sizeof(ULONG)
        );

    if ((status == STATUS_ACCESS_DENIED) && (KsiLevel() == KphLevelMax))
    {
        status = KphSetInformationThread(
            ThreadHandle,
            KphThreadPriorityBoost,
            &priorityBoost,
            sizeof(ULONG)
            );
    }

    return status;
}

NTSTATUS PhSetThreadIdealProcessor(
    _In_ HANDLE ThreadHandle,
    _In_ PPROCESSOR_NUMBER ProcessorNumber,
    _Out_opt_ PPROCESSOR_NUMBER PreviousIdealProcessor
    )
{
    NTSTATUS status;
    PROCESSOR_NUMBER processorNumber;

    processorNumber = *ProcessorNumber;
    status = NtSetInformationThread(
        ThreadHandle,
        ThreadIdealProcessorEx,
        &processorNumber,
        sizeof(PROCESSOR_NUMBER)
        );

    if ((status == STATUS_ACCESS_DENIED) && (KsiLevel() == KphLevelMax))
    {
        status = KphSetInformationThread(
            ThreadHandle,
            KphThreadIdealProcessorEx,
            &processorNumber,
            sizeof(PROCESSOR_NUMBER)
            );
    }

    if (PreviousIdealProcessor)
        *PreviousIdealProcessor = processorNumber;

    return status;
}

NTSTATUS PhSetThreadGroupAffinity(
    _In_ HANDLE ThreadHandle,
    _In_ GROUP_AFFINITY GroupAffinity
    )
{
    NTSTATUS status;

    status = NtSetInformationThread(
        ThreadHandle,
        ThreadGroupInformation,
        &GroupAffinity,
        sizeof(GROUP_AFFINITY)
        );

    if ((status == STATUS_ACCESS_DENIED) && (KsiLevel() == KphLevelMax))
    {
        status = KphSetInformationThread(
            ThreadHandle,
            KphThreadGroupInformation,
            &GroupAffinity,
            sizeof(GROUP_AFFINITY)
            );
    }

    return status;
}

/**
 * The PhGetThreadLastSystemCall function returns the last system call of a thread.
 *
 * \param ThreadHandle A handle to the thread.
 * \param LastSystemCall The last system call of the thread.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhGetThreadLastSystemCall(
    _In_ HANDLE ThreadHandle,
    _Out_ PTHREAD_LAST_SYSCALL_INFORMATION LastSystemCall
    )
{
    if (WindowsVersion < WINDOWS_8)
    {
        return NtQueryInformationThread(
            ThreadHandle,
            ThreadLastSystemCall,
            LastSystemCall,
            RTL_SIZEOF_THROUGH_FIELD(THREAD_LAST_SYSCALL_INFORMATION, Pad),
            NULL
            );
    }
    else
    {
        return NtQueryInformationThread(
            ThreadHandle,
            ThreadLastSystemCall,
            LastSystemCall,
            sizeof(THREAD_LAST_SYSCALL_INFORMATION),
            NULL
            );
    }
}

// rev from Advapi32!ImpersonateAnonymousToken (dmex)
/**
 * The PhCreateImpersonationToken function creates an anonymous logon token.
 *
 * \param ThreadHandle A handle to the thread.
 * \param TokenHandle A handle to the token.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhCreateImpersonationToken(
    _In_ HANDLE ThreadHandle,
    _Out_ PHANDLE TokenHandle
    )
{
    NTSTATUS status;
    HANDLE tokenHandle;
    SECURITY_QUALITY_OF_SERVICE securityService;

    status = PhRevertImpersonationToken(ThreadHandle);

    if (!NT_SUCCESS(status))
        return status;

    securityService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    securityService.ImpersonationLevel = SecurityImpersonation;
    securityService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    securityService.EffectiveOnly = FALSE;

    status = NtImpersonateThread(
        ThreadHandle,
        ThreadHandle,
        &securityService
        );

    if (!NT_SUCCESS(status))
        return status;

    status = PhOpenThreadToken(
        ThreadHandle,
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
        FALSE,
        &tokenHandle
        );

    if (NT_SUCCESS(status))
    {
        *TokenHandle = tokenHandle;
    }

    return status;
}

// rev from Advapi32!ImpersonateLoggedOnUser (dmex)
/**
 * The PhImpersonateToken function enables the specified thread to impersonate the security context of a token.
 *
 * \param ThreadHandle A handle to the thread.
 * \param TokenHandle A handle to the token.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhImpersonateToken(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE TokenHandle
    )
{
    NTSTATUS status;
    TOKEN_TYPE tokenType;
    ULONG returnLength;

    status = NtQueryInformationToken(
        TokenHandle,
        TokenType,
        &tokenType,
        sizeof(TOKEN_TYPE),
        &returnLength
        );

    if (!NT_SUCCESS(status))
        return status;

    if (tokenType == TokenPrimary)
    {
        SECURITY_QUALITY_OF_SERVICE securityService;
        OBJECT_ATTRIBUTES objectAttributes;
        HANDLE tokenHandle;

        InitializeObjectAttributes(
            &objectAttributes,
            NULL,
            OBJ_EXCLUSIVE,
            NULL,
            NULL
            );

        securityService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        securityService.ImpersonationLevel = SecurityImpersonation;
        securityService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        securityService.EffectiveOnly = FALSE;
        objectAttributes.SecurityQualityOfService = &securityService;

        status = NtDuplicateToken(
            TokenHandle,
            TOKEN_IMPERSONATE | TOKEN_QUERY,
            &objectAttributes,
            FALSE,
            TokenImpersonation,
            &tokenHandle
            );

        if (!NT_SUCCESS(status))
            return status;

        status = NtSetInformationThread(
            ThreadHandle,
            ThreadImpersonationToken,
            &tokenHandle,
            sizeof(HANDLE)
            );

        NtClose(tokenHandle);
    }
    else
    {
        status = NtSetInformationThread(
            ThreadHandle,
            ThreadImpersonationToken,
            &TokenHandle,
            sizeof(HANDLE)
            );
    }

    return status;
}

// rev from Advapi32!RevertToSelf (dmex)
/**
 * The PhRevertImpersonationToken function terminates the impersonation of a security context.
 *
 * \param ThreadHandle A handle to the thread.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhRevertImpersonationToken(
    _In_ HANDLE ThreadHandle
    )
{
    HANDLE tokenHandle = NULL;

    return NtSetInformationThread(
        ThreadHandle,
        ThreadImpersonationToken,
        &tokenHandle,
        sizeof(HANDLE)
        );
}

/**
 * Retrieves the last error status of a thread.
 *
 * \param ThreadHandle A handle to the thread.
 * \param ProcessHandle A handle to the process.
 * \param LastStatusValue The last status of the thread.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhGetThreadLastStatusValue(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE ProcessHandle,
    _Out_ PNTSTATUS LastStatusValue
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInfo;
#ifdef _WIN64
    BOOLEAN isWow64 = FALSE;
#endif

    if (!NT_SUCCESS(status = PhGetThreadBasicInformation(ThreadHandle, &basicInfo)))
        return status;

#ifdef _WIN64
    PhGetProcessIsWow64(ProcessHandle, &isWow64);

    if (isWow64)
    {
        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(WOW64_GET_TEB32(basicInfo.TebBaseAddress), UFIELD_OFFSET(TEB32, LastStatusValue)),
            LastStatusValue,
            sizeof(NTSTATUS),
            NULL
            );
    }
    else
#endif
    {
        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(basicInfo.TebBaseAddress, UFIELD_OFFSET(TEB, LastStatusValue)), // LastErrorValue/ExceptionCode
            LastStatusValue,
            sizeof(NTSTATUS),
            NULL
            );
    }

    return status;
}

/**
 * Retrieves statistics about COM multi-threaded apartment (MTA) usage in a process.
 *
 * \param[in] ProcessHandle A handle to the process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ access.
 * \param[out] MTAInits The total number of MTA references in the process.
 * \param[out] MTAIncInits The number of MTA references from CoIncrementMTAUsage.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhGetProcessMTAUsage(
    _In_ HANDLE ProcessHandle,
    _Out_opt_ PULONG MTAInits,
    _Out_opt_ PULONG MTAIncInits
    )
{
    NTSTATUS status;
#ifdef _WIN64
    BOOLEAN isWow64;
#endif
    static PH_INITONCE initOnce = PH_INITONCE_INIT;
    static PMTA_USAGE_GLOBALS mtaUsageGlobals = NULL;

    if (!MTAInits && !MTAIncInits)
        return STATUS_INVALID_PARAMETER;

#ifdef _WIN64
    if (!NT_SUCCESS(status = PhGetProcessIsWow64(ProcessHandle, &isWow64)))
        return status;

    if (isWow64)
        return STATUS_NOT_SUPPORTED;
#endif

    if (PhBeginInitOnce(&initOnce))
    {
        if (WindowsVersion >= WINDOWS_8)
        {
            PVOID combase;
            PMTA_USAGE_GLOBALS (WINAPI* CoGetMTAUsageInfo_I)(VOID);

            if (combase = PhGetLoaderEntryDllBaseZ(L"combase.dll"))
            {
                // combase exports CoGetMTAUsageInfo as ordinal 70
                CoGetMTAUsageInfo_I = PhGetDllBaseProcedureAddress(combase, NULL, 70);

                if (CoGetMTAUsageInfo_I)
                {
                    // CoGetMTAUsageInfo returns addresses of several global variables we can read
                    mtaUsageGlobals = CoGetMTAUsageInfo_I();
                }
            }
        }

        PhEndInitOnce(&initOnce);
    }

    if (!mtaUsageGlobals)
        return STATUS_UNSUCCESSFUL;

    if (MTAInits)
    {
        status = NtReadVirtualMemory(
            ProcessHandle,
            mtaUsageGlobals->MTAInits,
            MTAInits,
            sizeof(ULONG),
            NULL
            );

        if (!NT_SUCCESS(status))
            return status;
    }

    if (MTAIncInits)
    {
        status = NtReadVirtualMemory(
            ProcessHandle,
            mtaUsageGlobals->MTAIncInits,
            MTAIncInits,
            sizeof(ULONG),
            NULL
            );

        if (!NT_SUCCESS(status))
            return status;
    }

    return STATUS_SUCCESS;
}

/**
 * Retrieves COM apartment flags and init count of a thread.
 *
 * \param[in] ThreadHandle A handle to the thread. The handle must have
 * THREAD_QUERY_LIMITED_INFORMATION access.
 * \param[in] ProcessHandle A handle to the process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ access.
 * \param[out] ApartmentFlags The COM apartment flags of the thread.
 * \param[out] ComInits The number of times the thread initialized COM.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhGetThreadApartmentFlags(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE ProcessHandle,
    _Out_ PULONG ApartmentFlags,
    _Out_opt_ PULONG ComInits
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInfo;
    PVOID apartmentStateOffset;
#ifdef _WIN64
    BOOLEAN isWow64 = FALSE;
#endif
    PVOID oletlsBaseAddress = NULL;

    if (!NT_SUCCESS(status = PhGetThreadBasicInformation(ThreadHandle, &basicInfo)))
        return status;

#ifdef _WIN64
    if (!NT_SUCCESS(status = PhGetProcessIsWow64(ProcessHandle, &isWow64)))
        return status;

    if (isWow64)
    {
        ULONG oletlsDataAddress32 = 0;

        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(WOW64_GET_TEB32(basicInfo.TebBaseAddress), UFIELD_OFFSET(TEB32, ReservedForOle)),
            &oletlsDataAddress32,
            sizeof(ULONG),
            NULL
            );

        oletlsBaseAddress = UlongToPtr(oletlsDataAddress32);
    }
    else
#endif
    {
        ULONG_PTR oletlsDataAddress = 0;

        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(basicInfo.TebBaseAddress, UFIELD_OFFSET(TEB, ReservedForOle)),
            &oletlsDataAddress,
            sizeof(ULONG_PTR),
            NULL
            );

        oletlsBaseAddress = (PVOID)oletlsDataAddress;
    }

    if (!NT_SUCCESS(status))
        return status;

    if (!oletlsBaseAddress)
    {
        // Return a special error to indicate that we successfully determined
        // that the thread has no associated COM state. (diversenok)
        return NTSTATUS_FROM_WIN32(CO_E_NOTINITIALIZED);
    }

#ifdef _WIN64
    if (isWow64)
        apartmentStateOffset = PTR_ADD_OFFSET(oletlsBaseAddress, UFIELD_OFFSET(SOleTlsData32, Flags));
    else
        apartmentStateOffset = PTR_ADD_OFFSET(oletlsBaseAddress, UFIELD_OFFSET(SOleTlsData, Flags));
#else
    apartmentStateOffset = PTR_ADD_OFFSET(oletlsBaseAddress, UFIELD_OFFSET(SOleTlsData, Flags));
#endif

    status = NtReadVirtualMemory(
        ProcessHandle,
        apartmentStateOffset,
        ApartmentFlags,
        sizeof(ULONG),
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    if (ComInits)
    {
        PVOID comInitsOffset;

#ifdef _WIN64
        if (isWow64)
            comInitsOffset = PTR_ADD_OFFSET(oletlsBaseAddress, UFIELD_OFFSET(SOleTlsData32, ComInits));
        else
            comInitsOffset = PTR_ADD_OFFSET(oletlsBaseAddress, UFIELD_OFFSET(SOleTlsData, ComInits));
#else
        comInitsOffset = PTR_ADD_OFFSET(oletlsBaseAddress, UFIELD_OFFSET(SOleTlsData, ComInits));
#endif

        status = NtReadVirtualMemory(
            ProcessHandle,
            comInitsOffset,
            ComInits,
            sizeof(ULONG),
            NULL
            );
    }

    return status;
}

/**
 * Determines COM apartment type of a thread, similar to CoGetApartmentType.
 *
 * \param[in] ThreadHandle A handle to the thread. The handle must have
 * THREAD_QUERY_LIMITED_INFORMATION access.
 * \param[in] ProcessHandle A handle to the process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ access.
 * \param[out] ApartmentInfo The COM apartment information of the thread.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhGetThreadApartment(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE ProcessHandle,
    _Out_ PPH_APARTMENT_INFO ApartmentInfo
    )
{
    NTSTATUS status;
    PH_APARTMENT_INFO info = { 0 };

    //
    // N.B. Most information about the thread's apartment comes from OLE TLS data in TEB.
    // Without it, threads can still implicitly belong to the multi-threaded apartment (MTA)
    // as long as one exists in the process. (diversenok)
    //

    // Read OLE TLS flags
    status = PhGetThreadApartmentFlags(ThreadHandle, ProcessHandle, &info.Flags, &info.ComInits);

    if (status == NTSTATUS_FROM_WIN32(CO_E_NOTINITIALIZED))
    {
        // For our purposes, no OLE TLS data is equivalent to empty flags
        info.Flags = 0;
        info.ComInits = 0;
        status = STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(status))
        return status;

    if (info.Flags & OLETLS_APARTMENTTHREADED)
    {
        //
        // N.B. Single-threaded apartments (STAs) belong to one of the three sub-types:
        //  - Main STA: the first (classic) STA created in the process. It has the responsibility of hosting
        //    all components with no ThreadingModel and ThreadingModel=Single (which are equivalent).
        //  - Classic STA: a reentrant single-threaded apartment, usually referred to as just STA.
        //  - Application STA (ASTA): a non-reentrant single-threaded apartment used primarily by WinRT.
        //

        if (info.Flags & OLETLS_APPLICATION_STA)
        {
            // The non-reentrancy requirement of ASTA means it cannot serve as the main STA
            info.Type = PH_APARTMENT_TYPE_APPLICATION_STA;
        }
        else
        {
            THREAD_BASIC_INFORMATION basicInfo;
            BOOLEAN isMainSta = FALSE;

            //
            // N.B. There is no flag to distinguish between main and non-main classic STAs.
            // Internally, CoGetApartmentType compares the caller's thread ID to the thread ID
            // stored in a private global variable (which we cannot access). Instead, we can
            // check if the specified thread owns the main STA window - a message-only window
            // with a known class and name. (diversenok)
            //

            if (NT_SUCCESS(PhGetThreadBasicInformation(ThreadHandle, &basicInfo)))
            {

                CLIENT_ID clientId;
                HWND hwnd = NULL;

                do
                {
                    // Find the next main STA window
                    hwnd = FindWindowExW(
                        HWND_MESSAGE,
                        hwnd,
                        L"OleMainThreadWndClass",
                        L"OleMainThreadWndName"
                        );

                    // Check if it belongs to the specified thread ID
                } while (hwnd && NT_SUCCESS(PhGetWindowClientId(hwnd, &clientId)) &&
                    (clientId.UniqueProcess != basicInfo.ClientId.UniqueProcess ||
                    clientId.UniqueThread != basicInfo.ClientId.UniqueThread));

                isMainSta = !!hwnd;
            }

            info.Type = isMainSta ? PH_APARTMENT_TYPE_MAIN_STA : PH_APARTMENT_TYPE_STA;
        }
    }
    else if (info.Flags & (OLETLS_MULTITHREADED | OLETLS_DISPATCHTHREAD))
    {
        // CoGetApartmentType treats explicit MTA threads and dispatch threads equally
        info.Type = PH_APARTMENT_TYPE_MTA;
    }
    else
    {
        //
        // N.B. The thread lacks an explicit apartment. A single MTA init, however, is
        // enough to put all apartmentless threads into implicit MTA. The existence of MTA
        // can be checked by reading the process-wide MTA usage counter. (diversenok)
        // 

        if (!NT_SUCCESS(status = PhGetProcessMTAUsage(ProcessHandle, &info.ComInits, NULL)))
            return status;

        if (info.ComInits > 0)
            info.Type = PH_APARTMENT_TYPE_IMPLICIT_MTA;
        else
            return NTSTATUS_FROM_WIN32(CO_E_NOTINITIALIZED);
    }

    //
    // N.B. Threads can temporarily enter the neutral apartment on top of their existing apartment.
    // Neutral apartment is often abbreviated to NA, NTA, or TNA. (diversenok)
    //

    info.InNeutral = !!(info.Flags & OLETLS_INNEUTRALAPT);

    *ApartmentInfo = info;
    return STATUS_SUCCESS;
}

// rev from advapi32!WctGetCOMInfo (dmex)
/**
 * If a thread is blocked on a COM call, we can retrieve COM ownership information using these functions. Retrieves COM information when a thread is blocked on a COM call.
 *
 * \param ThreadHandle A handle to the thread.
 * \param ProcessHandle A handle to a process.
 * \param ApartmentCallState The COM call information.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhGetThreadApartmentCallState(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE ProcessHandle,
    _Out_ PPH_COM_CALLSTATE ApartmentCallState
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInfo;
#ifdef _WIN64
    BOOLEAN isWow64 = FALSE;
#endif
    __typeof__(RTL_FIELD_TYPE(TEB, ReservedForOle)) oletlsBaseAddress = NULL;

    if (!NT_SUCCESS(status = PhGetThreadBasicInformation(ThreadHandle, &basicInfo)))
        return status;

#ifdef _WIN64
    PhGetProcessIsWow64(ProcessHandle, &isWow64);

    if (isWow64)
    {
        ULONG oletlsDataAddress32 = 0;

        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(WOW64_GET_TEB32(basicInfo.TebBaseAddress), UFIELD_OFFSET(TEB32, ReservedForOle)),
            &oletlsDataAddress32,
            sizeof(ULONG),
            NULL
            );

        oletlsBaseAddress = UlongToPtr(oletlsDataAddress32);
    }
    else
#endif
    {
        ULONG_PTR oletlsDataAddress = 0;

        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(basicInfo.TebBaseAddress, UFIELD_OFFSET(TEB, ReservedForOle)),
            &oletlsDataAddress,
            sizeof(ULONG_PTR),
            NULL
            );

        oletlsBaseAddress = (PVOID)oletlsDataAddress;
    }

    if (NT_SUCCESS(status) && oletlsBaseAddress)
    {
        typedef enum _CALL_STATE_TYPE
        {
            CALL_STATE_TYPE_OUTGOING, // tagOutgoingCallData
            CALL_STATE_TYPE_INCOMING, // tagIncomingCallData
            CALL_STATE_TYPE_ACTIVATION // tagOutgoingActivationData
        } CALL_STATE_TYPE;
        typedef struct tagOutgoingCallData // private
        {
            ULONG dwServerPID;
            ULONG dwServerTID;
        } tagOutgoingCallData, *PtagOutgoingCallData;
        typedef struct tagIncomingCallData // private
        {
            ULONG dwClientPID;
        } tagIncomingCallData, *PtagIncomingCallData;
        typedef struct tagOutgoingActivationData // private
        {
            GUID guidServer;
        } tagOutgoingActivationData, *PtagOutgoingActivationData;
        static HRESULT (WINAPI* CoGetCallState_I)( // rev
            _In_ CALL_STATE_TYPE Type,
            _Out_ PULONG OffSet
            ) = NULL;
        //static HRESULT (WINAPI* CoGetActivationState_I)( // rev
        //    _In_ LPCLSID Clsid,
        //    _In_ ULONG ClientTid,
        //    _Out_ PULONG ServerPid
        //    ) = NULL;
        static PH_INITONCE initOnce = PH_INITONCE_INIT;
        ULONG outgoingCallDataOffset = 0;
        ULONG incomingCallDataOffset = 0;
        ULONG outgoingActivationDataOffset = 0;
        tagOutgoingCallData outgoingCallData;
        tagIncomingCallData incomingCallData;
        tagOutgoingActivationData outgoingActivationData;

        if (PhBeginInitOnce(&initOnce))
        {
            PVOID baseAddress;

            if (baseAddress = PhGetLoaderEntryDllBaseZ(L"combase.dll"))
            {
                CoGetCallState_I = PhGetDllBaseProcedureAddress(baseAddress, "CoGetCallState", 0);
                //CoGetActivationState_I = PhGetDllBaseProcedureAddress(baseAddress, "CoGetActivationState", 0);
            }

            PhEndInitOnce(&initOnce);
        }

        memset(&outgoingCallData, 0, sizeof(tagOutgoingCallData));
        memset(&incomingCallData, 0, sizeof(tagIncomingCallData));
        memset(&outgoingActivationData, 0, sizeof(tagOutgoingActivationData));

        if (HR_SUCCESS(CoGetCallState_I(CALL_STATE_TYPE_OUTGOING, &outgoingCallDataOffset)) && outgoingCallDataOffset)
        {
            NtReadVirtualMemory(
                ProcessHandle,
                PTR_ADD_OFFSET(oletlsBaseAddress, outgoingCallDataOffset),
                &outgoingCallData,
                sizeof(tagOutgoingCallData),
                NULL
                );
        }

        if (HR_SUCCESS(CoGetCallState_I(CALL_STATE_TYPE_INCOMING, &incomingCallDataOffset)) && incomingCallDataOffset)
        {
            NtReadVirtualMemory(
                ProcessHandle,
                PTR_ADD_OFFSET(oletlsBaseAddress, incomingCallDataOffset),
                &incomingCallData,
                sizeof(tagIncomingCallData),
                NULL
                );
        }

        if (HR_SUCCESS(CoGetCallState_I(CALL_STATE_TYPE_ACTIVATION, &outgoingActivationDataOffset)) && outgoingActivationDataOffset)
        {
            NtReadVirtualMemory(
                ProcessHandle,
                PTR_ADD_OFFSET(oletlsBaseAddress, outgoingActivationDataOffset),
                &outgoingActivationData,
                sizeof(tagOutgoingActivationData),
                NULL
                );
        }

        memset(ApartmentCallState, 0, sizeof(PH_COM_CALLSTATE));
        ApartmentCallState->ServerPID = outgoingCallData.dwServerPID != 0 ? outgoingCallData.dwServerPID : ULONG_MAX;
        ApartmentCallState->ServerTID = outgoingCallData.dwServerTID != 0 ? outgoingCallData.dwServerTID : ULONG_MAX;
        ApartmentCallState->ClientPID = incomingCallData.dwClientPID != 0 ? incomingCallData.dwClientPID : ULONG_MAX;
        memcpy(&ApartmentCallState->ServerGuid, &outgoingActivationData.guidServer, sizeof(GUID));
    }
    else
    {
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

/**
 * Determines if a thread has an associated RPC state.
 *
 * \param[in] ThreadHandle A handle to the thread. The handle must have
 * THREAD_QUERY_LIMITED_INFORMATION access.
 * \param[in] ProcessHandle A handle to the process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ access.
 * \param[out] HasRpcState Whether the thread has allocated RPC state.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhGetThreadRpcState(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE ProcessHandle,
    _Out_ PBOOLEAN HasRpcState
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInfo;
#ifdef _WIN64
    BOOLEAN isWow64 = FALSE;
#endif

    if (!NT_SUCCESS(status = PhGetThreadBasicInformation(ThreadHandle, &basicInfo)))
        return status;

#ifdef _WIN64
    if (!NT_SUCCESS(status = PhGetProcessIsWow64(ProcessHandle, &isWow64)))
        return status;

    if (isWow64)
    {
        ULONG reservedForNtRpc32 = 0;

        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(WOW64_GET_TEB32(basicInfo.TebBaseAddress), UFIELD_OFFSET(TEB32, ReservedForNtRpc)),
            &reservedForNtRpc32,
            sizeof(ULONG),
            NULL
            );

        *HasRpcState = !!reservedForNtRpc32;
    }
    else
#endif
    {
        ULONG_PTR reservedForNtRpc = 0;

        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(basicInfo.TebBaseAddress, UFIELD_OFFSET(TEB, ReservedForNtRpc)),
            &reservedForNtRpc,
            sizeof(ULONG_PTR),
            NULL
            );

        *HasRpcState = !!reservedForNtRpc;
    }

    return status;
}

// rev from advapi32!WctGetCritSecInfo (dmex)
/**
 * Retrieves the thread identifier when a thread is blocked on a critical section.
 *
 * \param ThreadHandle A handle to the thread.
 * \param ProcessId The ID of a process.
 * \param ThreadId The ID of the thread owning the critical section.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhGetThreadCriticalSectionOwnerThread(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE ProcessId,
    _Out_ PULONG ThreadId
    )
{
    NTSTATUS status;
    PRTL_DEBUG_INFORMATION debugBuffer;

    if (WindowsVersion < WINDOWS_11)
        return STATUS_UNSUCCESSFUL;

    if (!(debugBuffer = RtlCreateQueryDebugBuffer(0, FALSE)))
        return STATUS_UNSUCCESSFUL;

    debugBuffer->CriticalSectionOwnerThread = ThreadHandle;

    status = RtlQueryProcessDebugInformation(
        ProcessId,
        RTL_QUERY_PROCESS_NONINVASIVE_CS_OWNER, // TODO: RTL_QUERY_PROCESS_CS_OWNER (dmex)
        debugBuffer
        );

    if (!NT_SUCCESS(status))
    {
        RtlDestroyQueryDebugBuffer(debugBuffer);
        return status;
    }

    if (!debugBuffer->Reserved[0])
    {
        RtlDestroyQueryDebugBuffer(debugBuffer);
        return STATUS_UNSUCCESSFUL;
    }

    *ThreadId = PtrToUlong(debugBuffer->Reserved[0]);

    RtlDestroyQueryDebugBuffer(debugBuffer);

    return STATUS_SUCCESS;
}

// rev from advapi32!WctGetSocketInfo (dmex)
/**
 * Retrieves the connection state when a thread is blocked on a socket.
 *
 * \param ThreadHandle A handle to the thread.
 * \param ProcessHandle A handle to a process.
 * \param ThreadSocketState The state of the socket.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhGetThreadSocketState(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE ProcessHandle,
    _Out_ PPH_THREAD_SOCKET_STATE ThreadSocketState
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInfo;
    BOOLEAN openedProcessHandle = FALSE;
#ifdef _WIN64
    BOOLEAN isWow64 = FALSE;
#endif
    __typeof__(RTL_FIELD_TYPE(TEB, WinSockData)) winsockHandleAddress = NULL;

    if (!NT_SUCCESS(status = PhGetThreadBasicInformation(ThreadHandle, &basicInfo)))
        return status;

#ifdef _WIN64
    PhGetProcessIsWow64(ProcessHandle, &isWow64);

    if (isWow64)
    {
        ULONG winsockDataAddress = 0;

        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(WOW64_GET_TEB32(basicInfo.TebBaseAddress), UFIELD_OFFSET(TEB32, WinSockData)),
            &winsockDataAddress,
            sizeof(ULONG),
            NULL
            );

        winsockHandleAddress = UlongToHandle(winsockDataAddress);
    }
    else
#endif
    {
        ULONG_PTR winsockDataAddress = 0;

        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(basicInfo.TebBaseAddress, UFIELD_OFFSET(TEB, WinSockData)),
            &winsockDataAddress,
            sizeof(ULONG_PTR),
            NULL
            );

        winsockHandleAddress = (HANDLE)winsockDataAddress;
    }

    if (NT_SUCCESS(status) && winsockHandleAddress)
    {
        static LONG (WINAPI* LPFN_WSASTARTUP)(
            _In_ WORD wVersionRequested,
            _Out_ PVOID* lpWSAData
            );
        static LONG (WINAPI* LPFN_GETSOCKOPT)(
            _In_ UINT_PTR s,
            _In_ LONG level,
            _In_ LONG optname,
            _Out_writes_bytes_(*optlen) char FAR* optval,
            _Inout_ LONG FAR* optlen
            );
        static LONG (WINAPI* LPFN_CLOSESOCKET)(
            _In_ ULONG_PTR s
            );
        static LONG (WINAPI* LPFN_WSACLEANUP)(
            void
            );
        static PH_INITONCE initOnce = PH_INITONCE_INIT;
        #ifndef WINSOCK_VERSION
        #define WINSOCK_VERSION MAKEWORD(2,2)
        #endif
        #ifndef SOCKET_ERROR
        #define SOCKET_ERROR (-1)
        #endif
        #ifndef SOL_SOCKET
        #define SOL_SOCKET 0xffff
        #endif
        #ifndef SO_BSP_STATE
        #define SO_BSP_STATE 0x1009
        #endif
        typedef struct _SOCKET_ADDRESS
        {
            _Field_size_bytes_(iSockaddrLength) PVOID lpSockaddr;
            // _When_(lpSockaddr->sa_family == AF_INET, _Field_range_(>=, sizeof(SOCKADDR_IN)))
            // _When_(lpSockaddr->sa_family == AF_INET6, _Field_range_(>=, sizeof(SOCKADDR_IN6)))
            LONG iSockaddrLength;
        } SOCKET_ADDRESS, *PSOCKET_ADDRESS, *LPSOCKET_ADDRESS;
        typedef struct _CSADDR_INFO
        {
            SOCKET_ADDRESS LocalAddr;
            SOCKET_ADDRESS RemoteAddr;
            LONG iSocketType;
            LONG iProtocol;
        } CSADDR_INFO, *PCSADDR_INFO, FAR* LPCSADDR_INFO;
        PVOID wsaStartupData;
        HANDLE winsockTargetHandle;

        if (PhBeginInitOnce(&initOnce))
        {
            PVOID baseAddress;

            if (baseAddress = PhLoadLibrary(L"ws2_32.dll"))
            {
                LPFN_WSASTARTUP = PhGetDllBaseProcedureAddress(baseAddress, "WSAStartup", 0);
                LPFN_GETSOCKOPT = PhGetDllBaseProcedureAddress(baseAddress, "getsockopt", 0);
                //LPFN_GETSOCKNAME = PhGetDllBaseProcedureAddress(baseAddress, "getsockname", 0);
                //LPFN_GETPEERNAME = PhGetDllBaseProcedureAddress(baseAddress, "getpeername", 0);
                LPFN_CLOSESOCKET = PhGetDllBaseProcedureAddress(baseAddress, "closesocket", 0);
                LPFN_WSACLEANUP = PhGetDllBaseProcedureAddress(baseAddress, "WSACleanup", 0);
            }

            PhEndInitOnce(&initOnce);
        }

        if (LPFN_WSASTARTUP(WINSOCK_VERSION, &wsaStartupData) != 0)
        {
            status = STATUS_UNSUCCESSFUL;
            goto CleanupExit;
        }

        status = NtDuplicateObject(
            ProcessHandle,
            winsockHandleAddress,
            NtCurrentProcess(),
            &winsockTargetHandle,
            0,
            0,
            DUPLICATE_SAME_ACCESS
            );

        if (NT_SUCCESS(status))
        {
            ULONG returnLength;
            OBJECT_BASIC_INFORMATION winsockTargetBasicInfo;
            INT winsockAddressInfoLength = sizeof(CSADDR_INFO);
            CSADDR_INFO winsockAddressInfo;

            memset(&winsockTargetBasicInfo, 0, sizeof(OBJECT_BASIC_INFORMATION));
            NtQueryObject(
                winsockTargetHandle,
                ObjectBasicInformation,
                &winsockTargetBasicInfo,
                sizeof(OBJECT_BASIC_INFORMATION),
                &returnLength
                );

            if (winsockTargetBasicInfo.HandleCount > 2)
            {
                if (LPFN_GETSOCKOPT((UINT_PTR)winsockTargetHandle, SOL_SOCKET, SO_BSP_STATE, (PCHAR)&winsockAddressInfo, &winsockAddressInfoLength) != SOCKET_ERROR)
                {
                    if (winsockAddressInfo.iProtocol == 6)
                    {
                        if (winsockAddressInfo.LocalAddr.lpSockaddr && winsockAddressInfo.RemoteAddr.lpSockaddr)
                            *ThreadSocketState = PH_THREAD_SOCKET_STATE_SHARED;
                        else
                            *ThreadSocketState = PH_THREAD_SOCKET_STATE_DISCONNECTED;
                    }
                    else
                        *ThreadSocketState = PH_THREAD_SOCKET_STATE_NOT_TCPIP;
                }
                else
                {
                    status = STATUS_UNSUCCESSFUL; // WSAGetLastError();
                }
            }
            else
            {
                status = STATUS_UNSUCCESSFUL;
            }

            LPFN_CLOSESOCKET((UINT_PTR)winsockTargetHandle);

            NtClose(winsockTargetHandle);
        }

        LPFN_WSACLEANUP();
    }
    else
    {
        status = STATUS_UNSUCCESSFUL;
    }

CleanupExit:
    if (openedProcessHandle)
        NtClose(ProcessHandle);

    return status;
}

NTSTATUS PhGetThreadStackLimits(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE ProcessHandle,
    _Out_ PULONG_PTR LowPart,
    _Out_ PULONG_PTR HighPart
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInfo;
    NT_TIB ntTib;
#ifdef _WIN64
    BOOLEAN isWow64 = FALSE;
#endif

    if (!NT_SUCCESS(status = PhGetThreadBasicInformation(ThreadHandle, &basicInfo)))
        return status;

    memset(&ntTib, 0, sizeof(NT_TIB));

#ifdef _WIN64
    PhGetProcessIsWow64(ProcessHandle, &isWow64);

    if (isWow64)
    {
        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(WOW64_GET_TEB32(basicInfo.TebBaseAddress), UFIELD_OFFSET(TEB32, NtTib)),
            &ntTib,
            sizeof(NT_TIB32),
            NULL
            );
    }
    else
#endif
    {
        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(basicInfo.TebBaseAddress, UFIELD_OFFSET(TEB, NtTib)),
            &ntTib,
            sizeof(NT_TIB),
            NULL
            );
    }

    if (NT_SUCCESS(status))
    {
#ifdef _WIN64
        if (isWow64)
        {
            PNT_TIB32 ntTib32 = (PNT_TIB32)&ntTib;
            *LowPart = (ULONG_PTR)UlongToPtr(ntTib32->StackLimit);
            *HighPart = (ULONG_PTR)UlongToPtr(ntTib32->StackBase);
        }
        else
        {
            *LowPart = (ULONG_PTR)ntTib.StackLimit;
            *HighPart = (ULONG_PTR)ntTib.StackBase;
        }
#else
        *LowPart = (ULONG_PTR)ntTib.StackLimit;
        *HighPart = (ULONG_PTR)ntTib.StackBase;
#endif
    }

    return status;
}

NTSTATUS PhGetThreadStackSize(
    _In_ HANDLE ThreadHandle,
    _In_ HANDLE ProcessHandle,
    _Out_ PULONG_PTR StackUsage,
    _Out_ PULONG_PTR StackLimit
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInfo;
    NT_TIB ntTib;
#ifdef _WIN64
    BOOLEAN isWow64 = FALSE;
#endif

    if (!NT_SUCCESS(status = PhGetThreadBasicInformation(ThreadHandle, &basicInfo)))
        return status;

    memset(&ntTib, 0, sizeof(NT_TIB));

#ifdef _WIN64
    PhGetProcessIsWow64(ProcessHandle, &isWow64);

    if (isWow64)
    {
        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(WOW64_GET_TEB32(basicInfo.TebBaseAddress), UFIELD_OFFSET(TEB32, NtTib)),
            &ntTib,
            sizeof(NT_TIB32),
            NULL
            );
    }
    else
#endif
    {
        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(basicInfo.TebBaseAddress, UFIELD_OFFSET(TEB, NtTib)),
            &ntTib,
            sizeof(NT_TIB),
            NULL
            );
    }

    if (NT_SUCCESS(status))
    {
        MEMORY_BASIC_INFORMATION memoryBasicInformation;
        PVOID stackBaseAddress = NULL;
        PVOID stackLimitAddress = NULL;

#ifdef _WIN64
        if (isWow64)
        {
            PNT_TIB32 ntTib32 = (PNT_TIB32)&ntTib;
            stackBaseAddress = UlongToPtr(ntTib32->StackBase);
            stackLimitAddress = UlongToPtr(ntTib32->StackLimit);
        }
        else
        {
            stackBaseAddress = ntTib.StackBase;
            stackLimitAddress = ntTib.StackLimit;
        }
#else
        stackBaseAddress = ntTib.StackBase;
        stackLimitAddress = ntTib.StackLimit;
#endif
        memset(&memoryBasicInformation, 0, sizeof(MEMORY_BASIC_INFORMATION));

        status = NtQueryVirtualMemory(
            ProcessHandle,
            stackLimitAddress,
            MemoryBasicInformation,
            &memoryBasicInformation,
            sizeof(MEMORY_BASIC_INFORMATION),
            NULL
            );

        if (NT_SUCCESS(status))
        {
            // TEB->DeallocationStack == memoryBasicInfo.AllocationBase
            *StackUsage = (ULONG_PTR)PTR_SUB_OFFSET(stackBaseAddress, stackLimitAddress);
            *StackLimit = (ULONG_PTR)PTR_SUB_OFFSET(stackBaseAddress, memoryBasicInformation.AllocationBase);
        }
    }

    return status;
}

NTSTATUS PhGetThreadIsFiber(
    _In_ HANDLE ThreadHandle,
    _In_opt_ HANDLE ProcessHandle,
    _Out_ PBOOLEAN ThreadIsFiber
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInfo;
    BOOLEAN openedProcessHandle = FALSE;
#ifdef _WIN64
    BOOLEAN isWow64 = FALSE;
#endif
    LONG flags = 0;

    if (!NT_SUCCESS(status = PhGetThreadBasicInformation(ThreadHandle, &basicInfo)))
        return status;

    if (!ProcessHandle)
    {
        if (!NT_SUCCESS(status = PhOpenProcess(
            &ProcessHandle,
            PROCESS_VM_READ | (WindowsVersion > WINDOWS_7 ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION),
            basicInfo.ClientId.UniqueProcess
            )))
            return status;

        openedProcessHandle = TRUE;
    }

#ifdef _WIN64
    PhGetProcessIsWow64(ProcessHandle, &isWow64);

    if (isWow64)
    {
        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(WOW64_GET_TEB32(basicInfo.TebBaseAddress), UFIELD_OFFSET(TEB32, SameTebFlags)),
            &flags,
            sizeof(USHORT),
            NULL
            );
    }
    else
#endif
    {
        status = NtReadVirtualMemory(
            ProcessHandle,
            PTR_ADD_OFFSET(basicInfo.TebBaseAddress, UFIELD_OFFSET(TEB, SameTebFlags)),
            &flags,
            sizeof(USHORT),
            NULL
            );
    }

    if (NT_SUCCESS(status))
    {
        *ThreadIsFiber = _bittest(&flags, 2); // HasFiberData offset (dmex)
    }

    if (openedProcessHandle)
        NtClose(ProcessHandle);

    return status;
}

// rev from SwitchToThread (dmex)
/**
 * Causes the calling thread to yield execution to another thread that is ready to run on the current processor. The operating system selects the next thread to be executed.
 *
 * \remarks The operating system will not switch execution to another processor, even if that processor is idle or is running a thread of lower priority.
 *
 * \return If calling the SwitchToThread function caused the operating system to switch execution to another thread, the return value is nonzero.
 * \rthere are no other threads ready to execute, the operating system does not switch execution to another thread, and the return value is zero.
 */
BOOLEAN PhSwitchToThread(
    VOID
    )
{
    LARGE_INTEGER interval = { 0 };

    return PhDelayExecutionEx(FALSE, &interval) != STATUS_NO_YIELD_PERFORMED;
}

NTSTATUS PhGetProcessRuntimeLibrary(
    _In_ HANDLE ProcessHandle,
    _Out_ PPH_PROCESS_RUNTIME_LIBRARY* RuntimeLibrary,
    _Out_opt_ PBOOLEAN IsWow64Process
    )
{
    static PH_PROCESS_RUNTIME_LIBRARY NativeRuntime =
    {
        PH_STRINGREF_INIT(L"\\SystemRoot\\System32\\ntdll.dll"),
        PH_STRINGREF_INIT(L"\\SystemRoot\\System32\\kernel32.dll"),
        PH_STRINGREF_INIT(L"\\SystemRoot\\System32\\user32.dll"),
    };
#ifdef _WIN64
    static PH_PROCESS_RUNTIME_LIBRARY Wow64Runtime =
    {
        PH_STRINGREF_INIT(L"\\SystemRoot\\SysWOW64\\ntdll.dll"),
        PH_STRINGREF_INIT(L"\\SystemRoot\\SysWOW64\\kernel32.dll"),
        PH_STRINGREF_INIT(L"\\SystemRoot\\SysWOW64\\user32.dll"),
    };
#ifdef _M_ARM64
    static PH_PROCESS_RUNTIME_LIBRARY Arm32Runtime =
    {
        PH_STRINGREF_INIT(L"\\SystemRoot\\SysArm32\\ntdll.dll"),
        PH_STRINGREF_INIT(L"\\SystemRoot\\SysArm32\\kernel32.dll"),
        PH_STRINGREF_INIT(L"\\SystemRoot\\SysArm32\\user32.dll"),
    };
    static PH_PROCESS_RUNTIME_LIBRARY Chpe32Runtime =
    {
        PH_STRINGREF_INIT(L"\\SystemRoot\\SyChpe32\\ntdll.dll"),
        PH_STRINGREF_INIT(L"\\SystemRoot\\SyChpe32\\kernel32.dll"),
        PH_STRINGREF_INIT(L"\\SystemRoot\\SyChpe32\\user32.dll"),
    };
#endif
#endif

    *RuntimeLibrary = &NativeRuntime;

    if (IsWow64Process)
        *IsWow64Process = FALSE;

#ifdef _WIN64
    NTSTATUS status;
#ifdef _M_ARM64
    USHORT machine;

    status = PhGetProcessArchitecture(ProcessHandle, &machine);

    if (!NT_SUCCESS(status))
        return status;

    if (machine != IMAGE_FILE_MACHINE_TARGET_HOST)
    {
        switch (machine)
        {
        case IMAGE_FILE_MACHINE_I386:
        case IMAGE_FILE_MACHINE_CHPE_X86:
            {
                *RuntimeLibrary = &Chpe32Runtime;

                if (IsWow64Process)
                    *IsWow64Process = TRUE;
            }
            break;
        case IMAGE_FILE_MACHINE_ARMNT:
            {
                *RuntimeLibrary = &Arm32Runtime;

                if (IsWow64Process)
                    *IsWow64Process = TRUE;
            }
            break;
        case IMAGE_FILE_MACHINE_AMD64:
        case IMAGE_FILE_MACHINE_ARM64:
            break;
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }
#else
    BOOLEAN isWow64 = FALSE;

    status = PhGetProcessIsWow64(ProcessHandle, &isWow64);

    if (!NT_SUCCESS(status))
        return status;

    if (isWow64)
    {
        *RuntimeLibrary = &Wow64Runtime;

        if (IsWow64Process)
            *IsWow64Process = TRUE;
    }
#endif
#endif

    return STATUS_SUCCESS;
}

// AmalgamLoader Manual Mapping Implementation - 1:1 Copy
// Function pointer types for LoadLibraryA and GetProcAddress
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

// DLL entry point function signature
typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

// Data structure passed to the remote process containing all necessary information
// for manual mapping. This is the "mp" parameter referenced in the tutorial.
typedef struct _MANUAL_INJECT
{
    PVOID ImageBase;                        // Base address where DLL is mapped in target process
    PIMAGE_NT_HEADERS NtHeaders;           // Pointer to NT headers in target process
    PIMAGE_BASE_RELOCATION BaseRelocation; // Pointer to relocation table in target process
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory; // Pointer to import table in target process
    pLoadLibraryA fnLoadLibraryA;          // Function pointer to LoadLibraryA in target process
    pGetProcAddress fnGetProcAddress;      // Function pointer to GetProcAddress in target process
    HINSTANCE hMod;                        // Status reporting field for debugging (as per tutorial)
}MANUAL_INJECT, * PMANUAL_INJECT;

// ============================================================================
// POSITION-INDEPENDENT SHELLCODE FUNCTION - 1:1 AmalgamLoader Copy
// ============================================================================
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

	// Validate input parameter - return FALSE if invalid
	if (!ManualInject) {
		return FALSE;
	}

	// ====================================================================
	// STEP 2: HANDLE RELOCATIONS
	// ====================================================================
	// Every PE file has a preferred ImageBase address it wants to be loaded at.
	// If we can't load it there, we need to fix up absolute addresses using
	// the base relocation table. This applies the "delta" (difference between
	// preferred and actual load address) to all absolute addresses.
	
	pIBR = ManualInject->BaseRelocation;
	delta = (DWORD64)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);

	// Only process relocations if they exist and delta is not zero
	if (pIBR && delta != 0)
	{
		// Each relocation block contains multiple relocation entries
		while (pIBR->VirtualAddress)
		{
			if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
			{
				// Calculate number of relocations in this block
				// Each relocation entry is 2 bytes (WORD), subtract the 8-byte block header
				count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				list = (PWORD)(pIBR + 1); // Point to first relocation entry after header

				// Process each relocation entry in this block
				for (i = 0; i < count; i++)
				{
					if (list[i])
					{
						// Extract relocation type (upper 4 bits) and offset (lower 12 bits)
						WORD type = (list[i] >> 12) & 0xF;
						WORD offset = list[i] & 0xFFF;
						
						// For 64-bit, we only handle IMAGE_REL_BASED_DIR64 relocations
						if (type == IMAGE_REL_BASED_DIR64)
						{
							// Apply delta to the 64-bit address at this location
							ptr = (DWORD64*)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + offset));
							*ptr += delta;
						}
						// Ignore other relocation types for 64-bit loader
					}
				}
			}

			// Move to next relocation block
			pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
		}
	}

	// ====================================================================
	// STEP 3: HANDLE IMPORTS
	// ====================================================================
	// The DLL needs to import functions from other DLLs (like kernel32.dll).
	// We need to:
	// 1. Load each required DLL using LoadLibraryA
	// 2. Get addresses of imported functions using GetProcAddress
	// 3. Update the Import Address Table (IAT) with these addresses
	//
	// OriginalFirstThunk = Import Name Table (function names/ordinals)
	// FirstThunk = Import Address Table (gets filled with actual addresses)
	
	pIID = ManualInject->ImportDirectory;

	// Process imports only if import directory exists
	if (pIID)
	{
		// Loop through each DLL that needs to be imported
		while (pIID->Name)
		{
			// Get pointers to the thunk tables (as shown in tutorial)
			DWORD64* pThunk = (DWORD64*)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
			DWORD64* pFunc = (DWORD64*)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

			// If OriginalFirstThunk not defined, use FirstThunk (as per tutorial)
			if (!pThunk) { pThunk = pFunc; }

			// Load the required DLL module
			char* importName = (char*)((LPBYTE)ManualInject->ImageBase + pIID->Name);
			hModule = ManualInject->fnLoadLibraryA(importName);

			if (!hModule)
			{
				ManualInject->hMod = (HINSTANCE)0x404; // Module loading failed
				return FALSE;
			}

			// Process each function import in this DLL (as per tutorial)
			for (; *pThunk; ++pThunk, ++pFunc)
			{
				if (*pThunk & IMAGE_ORDINAL_FLAG64)
				{
					// Import by ordinal (64-bit) - function imported by number
					Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(*pThunk & 0xFFFF));
					if (!Function)
					{
						ManualInject->hMod = (HINSTANCE)0x405; // Ordinal import failed
						return FALSE;
					}
					*pFunc = Function; // Update IAT with function address
				}
				else
				{
					// Import by name (64-bit) - function imported by name
					pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + *pThunk);
					Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
					if (!Function)
					{
						ManualInject->hMod = (HINSTANCE)0x406; // Name import failed
						return FALSE;
					}
					*pFunc = Function; // Update IAT with function address
				}
			}

			pIID++; // Move to next import descriptor
		}
	}

	// ====================================================================
	// STEP 4: EXECUTE TLS CALLBACKS
	// ====================================================================
	// Thread Local Storage (TLS) callbacks are executed before DLL main.
	// These are used for thread-specific initialization. Some malware uses
	// TLS callbacks to execute code before debuggers detect the main entry point.
	
	if (ManualInject->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		PIMAGE_TLS_DIRECTORY64 pTLS = (PIMAGE_TLS_DIRECTORY64)((LPBYTE)ManualInject->ImageBase + 
			ManualInject->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		
		if (pTLS && pTLS->AddressOfCallBacks)
		{
			PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)pTLS->AddressOfCallBacks;
			// Execute each TLS callback with DLL_PROCESS_ATTACH
			for (; pCallback && *pCallback; ++pCallback)
			{
				(*pCallback)((LPVOID)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
			}
		}
	}

	// ====================================================================
	// STEP 5: CALL DLL MAIN
	// ====================================================================
	// Finally, call the DLL's entry point (DllMain) with DLL_PROCESS_ATTACH.
	// This is equivalent to what LoadLibrary does as the final step.
	
	if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		// Get pointer to DLL entry point
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		
		// Call entry point with proper error handling
		__try
		{
			BOOL result = EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
			
			// Set status for debugging purposes
			ManualInject->hMod = result ? (HINSTANCE)ManualInject->ImageBase : (HINSTANCE)0x407;
			
			return result;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			// DLL entry point crashed
			ManualInject->hMod = (HINSTANCE)0x408;
			return FALSE;
		}
	}

	// If no entry point, still consider it successful
	ManualInject->hMod = (HINSTANCE)ManualInject->ImageBase;
	return TRUE;
}

// Marker function to calculate LoadDll function size
DWORD WINAPI LoadDllEnd()
{
	return 0;
}

/**
 * Causes a process to load a DLL.
 *
 * \param ProcessHandle A handle to a process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ
 * and PROCESS_VM_WRITE access.
 * \param FileName The file name of the DLL to inject.
 * \param LoadDllUsingApcThread Queues an APC (Asynchronous Procedure Call) when calling LoadLibraryW.
 * \param Timeout The timeout, in milliseconds, for the process to load the DLL.
 *
 * \remarks If the process does not load the DLL before the timeout expires it may crash. Choose the
 * timeout value carefully.
 */
NTSTATUS PhLoadDllProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PPH_STRINGREF FileName,
    _In_ BOOLEAN LoadDllUsingApcThread,
    _In_opt_ ULONG Timeout
    )
{
    UNREFERENCED_PARAMETER(FileName);
    UNREFERENCED_PARAMETER(LoadDllUsingApcThread);

    // Find first DLL in same directory as executable
    WCHAR exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH))
        return STATUS_UNSUCCESSFUL;

    // Get directory path
    WCHAR* lastSlash = wcsrchr(exePath, L'\\');
    if (!lastSlash)
        return STATUS_UNSUCCESSFUL;
    
    *lastSlash = L'\0';
    
    // Look for first *.dll file
    WCHAR searchPath[MAX_PATH];
    swprintf_s(searchPath, MAX_PATH, L"%s\\*.dll", exePath);
    
    WIN32_FIND_DATAW findData;
    HANDLE findHandle = FindFirstFileW(searchPath, &findData);
    if (findHandle == INVALID_HANDLE_VALUE)
        return STATUS_NOT_FOUND;
    
    WCHAR dllPath[MAX_PATH];
    swprintf_s(dllPath, MAX_PATH, L"%s\\%s", exePath, findData.cFileName);
    FindClose(findHandle);

    // Now use AmalgamLoader's 1:1 implementation
    HANDLE hFile;
    DWORD FileSize, read, i;
    PVOID buffer, image;
    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS pINH;
    MANUAL_INJECT ManualInject;
    PVOID mem1;
    HANDLE hThread;

    // Load DLL file into buffer (AmalgamLoader style)
    hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return STATUS_UNSUCCESSFUL;

    FileSize = GetFileSize(hFile, NULL);
    buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }
    CloseHandle(hFile);

    // PE validation (AmalgamLoader style)
    pIDH = (PIMAGE_DOS_HEADER)buffer;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Allocate memory in target process (AmalgamLoader style)
    image = VirtualAllocEx(ProcessHandle, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Copy PE header (AmalgamLoader style)
    if (!WriteProcessMemory(ProcessHandle, image, buffer, 0x1000, NULL))
    {
        VirtualFreeEx(ProcessHandle, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Copy sections (AmalgamLoader style)
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pINH);
    for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
    {
        if (pSectionHeader->PointerToRawData)
        {
            WriteProcessMemory(ProcessHandle, 
                (PVOID)((LPBYTE)image + pSectionHeader->VirtualAddress), 
                (PVOID)((LPBYTE)buffer + pSectionHeader->PointerToRawData), 
                pSectionHeader->SizeOfRawData, NULL);
        }
        pSectionHeader++;
    }

    // Calculate loader size (AmalgamLoader style)
    DWORD64 loadDllSize = (DWORD64)LoadDllEnd - (DWORD64)LoadDll;
    if (loadDllSize <= 0 || loadDllSize > 0x10000)
        loadDllSize = 2048;
    
    DWORD totalLoaderSize = (DWORD)(sizeof(MANUAL_INJECT) + loadDllSize + 512);
    
    mem1 = VirtualAllocEx(ProcessHandle, NULL, totalLoaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem1)
    {
        VirtualFreeEx(ProcessHandle, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Setup ManualInject structure (AmalgamLoader style)
    memset(&ManualInject, 0, sizeof(MANUAL_INJECT));
    ManualInject.ImageBase = image;
    ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
    ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    // Get function addresses in target process (kernel32.dll is loaded at same address in all processes)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        VirtualFreeEx(ProcessHandle, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }
    
    ManualInject.fnLoadLibraryA = (pLoadLibraryA)GetProcAddress(hKernel32, "LoadLibraryA");
    ManualInject.fnGetProcAddress = (pGetProcAddress)GetProcAddress(hKernel32, "GetProcAddress");
    
    if (!ManualInject.fnLoadLibraryA || !ManualInject.fnGetProcAddress)
    {
        VirtualFreeEx(ProcessHandle, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Write ManualInject structure (AmalgamLoader style)
    if (!WriteProcessMemory(ProcessHandle, mem1, &ManualInject, sizeof(MANUAL_INJECT), NULL))
    {
        VirtualFreeEx(ProcessHandle, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Write LoadDll function (AmalgamLoader style) - Fix pointer arithmetic
    PVOID functionAddress = (PVOID)((LPBYTE)mem1 + sizeof(MANUAL_INJECT));
    if (!WriteProcessMemory(ProcessHandle, functionAddress, LoadDll, (SIZE_T)loadDllSize, NULL))
    {
        VirtualFreeEx(ProcessHandle, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Create remote thread (AmalgamLoader style)
    hThread = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)functionAddress, mem1, 0, NULL);
    if (!hThread)
    {
        VirtualFreeEx(ProcessHandle, mem1, 0, MEM_RELEASE);
        VirtualFreeEx(ProcessHandle, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return STATUS_UNSUCCESSFUL;
    }

    // Wait for completion with error checking
    DWORD waitResult = WaitForSingleObject(hThread, Timeout ? Timeout : 10000);
    
    // Check thread exit code for debugging
    DWORD threadExitCode = 0;
    GetExitCodeThread(hThread, &threadExitCode);
    CloseHandle(hThread);
    
    // Read back the status to see what happened
    MANUAL_INJECT statusCheck;
    if (ReadProcessMemory(ProcessHandle, mem1, &statusCheck, sizeof(statusCheck), NULL))
    {
        // Check for specific error codes from AmalgamLoader
        if (statusCheck.hMod == (HINSTANCE)0x404)
        {
            // Module loading failed - this means the crash happened in LoadLibraryA call
            VirtualFreeEx(ProcessHandle, mem1, 0, MEM_RELEASE);
            VirtualFree(buffer, 0, MEM_RELEASE);
            return STATUS_UNSUCCESSFUL; // LoadLibraryA failed
        }
        else if (statusCheck.hMod == (HINSTANCE)0x405 || statusCheck.hMod == (HINSTANCE)0x406)
        {
            // Import resolution failed - crash in GetProcAddress calls
            VirtualFreeEx(ProcessHandle, mem1, 0, MEM_RELEASE);
            VirtualFree(buffer, 0, MEM_RELEASE);
            return STATUS_UNSUCCESSFUL; // GetProcAddress failed
        }
        else if (statusCheck.hMod == (HINSTANCE)0x407)
        {
            // DLL main returned FALSE
            VirtualFreeEx(ProcessHandle, mem1, 0, MEM_RELEASE);
            VirtualFree(buffer, 0, MEM_RELEASE);
            return STATUS_UNSUCCESSFUL; // DLL main failed
        }
        else if (statusCheck.hMod == (HINSTANCE)0x408)
        {
            // DLL main crashed
            VirtualFreeEx(ProcessHandle, mem1, 0, MEM_RELEASE);
            VirtualFree(buffer, 0, MEM_RELEASE);
            return STATUS_UNSUCCESSFUL; // DLL main crashed
        }
    }

    // Cleanup loader memory but keep DLL loaded (AmalgamLoader style)
    VirtualFreeEx(ProcessHandle, mem1, 0, MEM_RELEASE);
    VirtualFree(buffer, 0, MEM_RELEASE);

    return (waitResult == WAIT_OBJECT_0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


/**
 * Causes a process to unload a DLL.
 *
 * \param ProcessHandle A handle to a process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ
 * and PROCESS_VM_WRITE access.
 * \param BaseAddress The base address of the DLL to unload.
 * \param Timeout The timeout, in milliseconds, for the process to unload the DLL.
 */
NTSTATUS PhUnloadDllProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_opt_ ULONG Timeout
    )
{
    NTSTATUS status;
    HANDLE threadHandle;
    HANDLE powerRequestHandle = NULL;
    THREAD_BASIC_INFORMATION basicInfo;
    PVOID freeLibrary = NULL;
    PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;

    status = PhGetProcessRuntimeLibrary(
        ProcessHandle,
        &runtimeLibrary,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    // No point trying to set the load count on Windows 8 and higher, because NT now uses a DAG of
    // loader nodes. (wj32)
    if (WindowsVersion < WINDOWS_8)
    {
#ifdef _WIN64
        BOOLEAN isWow64 = FALSE;
#endif
        status = PhSetProcessModuleLoadCount(
            ProcessHandle,
            BaseAddress,
            1
            );

#ifdef _WIN64
        PhGetProcessIsWow64(ProcessHandle, &isWow64);

        if (isWow64 && status == STATUS_DLL_NOT_FOUND)
        {
            // The DLL might be 32-bit.
            status = PhSetProcessModuleLoadCount32(
                ProcessHandle,
                BaseAddress,
                1
                );
        }
#endif
        if (!NT_SUCCESS(status))
            return status;
    }

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->Kernel32FileName,
        "FreeLibrary",
        &freeLibrary,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    if (WindowsVersion >= WINDOWS_8)
    {
        status = PhCreateExecutionRequiredRequest(ProcessHandle, &powerRequestHandle);

        if (!NT_SUCCESS(status))
            return status;
    }

    status = PhCreateUserThread(
        ProcessHandle,
        NULL,
        THREAD_ALL_ACCESS,
        0,
        0,
        0,
        0,
        freeLibrary,
        BaseAddress,
        &threadHandle,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    status = PhWaitForSingleObject(threadHandle, Timeout);

    if (status == STATUS_WAIT_0)
    {
        status = PhGetThreadBasicInformation(threadHandle, &basicInfo);

        if (NT_SUCCESS(status))
            status = basicInfo.ExitStatus;
    }

    NtClose(threadHandle);

    if (powerRequestHandle)
        PhDestroyExecutionRequiredRequest(powerRequestHandle);

    return status;
}

/**
 * Sets an environment variable in a process.
 *
 * \param ProcessHandle A handle to a process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ
 * and PROCESS_VM_WRITE access.
 * \param Name The name of the environment variable to set.
 * \param Value The new value of the environment variable. If this parameter is NULL, the
 * environment variable is deleted.
 * \param Timeout The timeout, in milliseconds, for the process to set the environment variable.
 */
NTSTATUS PhSetEnvironmentVariableRemote(
    _In_ HANDLE ProcessHandle,
    _In_ PPH_STRINGREF Name,
    _In_opt_ PPH_STRINGREF Value,
    _In_opt_ PLARGE_INTEGER Timeout
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInformation;
    PVOID nameBaseAddress = NULL;
    PVOID valueBaseAddress = NULL;
    SIZE_T nameAllocationSize = 0;
    SIZE_T valueAllocationSize = 0;
    PVOID rtlExitUserThread = NULL;
    PVOID setEnvironmentVariableW = NULL;
    HANDLE threadHandle = NULL;
    HANDLE powerRequestHandle = NULL;
    PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;
#ifdef _WIN64
    BOOLEAN isWow64;
#endif

    nameAllocationSize = Name->Length + sizeof(UNICODE_NULL);

    if (Value)
        valueAllocationSize = Value->Length + sizeof(UNICODE_NULL);

    status = PhGetProcessRuntimeLibrary(
        ProcessHandle,
        &runtimeLibrary,
#ifdef _WIN64
        &isWow64
#else
        NULL
#endif
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->NtdllFileName,
        "RtlExitUserThread",
        &rtlExitUserThread,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->Kernel32FileName,
        "SetEnvironmentVariableW",
        &setEnvironmentVariableW,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = NtAllocateVirtualMemory(
        ProcessHandle,
        &nameBaseAddress,
        0,
        &nameAllocationSize,
        MEM_COMMIT,
        PAGE_READWRITE
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = NtWriteVirtualMemory(
        ProcessHandle,
        nameBaseAddress,
        Name->Buffer,
        Name->Length,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    if (Value)
    {
        status = NtAllocateVirtualMemory(
            ProcessHandle,
            &valueBaseAddress,
            0,
            &valueAllocationSize,
            MEM_COMMIT,
            PAGE_READWRITE
            );

        if (!NT_SUCCESS(status))
            goto CleanupExit;

        status = NtWriteVirtualMemory(
            ProcessHandle,
            valueBaseAddress,
            Value->Buffer,
            Value->Length,
            NULL
            );

        if (!NT_SUCCESS(status))
            goto CleanupExit;
    }

    if (WindowsVersion >= WINDOWS_8)
    {
        status = PhCreateExecutionRequiredRequest(ProcessHandle, &powerRequestHandle);

        if (!NT_SUCCESS(status))
            goto CleanupExit;
    }

    status = PhCreateUserThread(
        ProcessHandle,
        NULL,
        THREAD_ALL_ACCESS,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        0,
        0,
        0,
        rtlExitUserThread,
        LongToPtr(STATUS_SUCCESS),
        &threadHandle,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

#ifdef _WIN64
    if (isWow64)
    {
        status = RtlQueueApcWow64Thread(
            threadHandle,
            setEnvironmentVariableW,
            nameBaseAddress,
            valueBaseAddress,
            NULL
            );
    }
    else
    {
#endif
        status = NtQueueApcThread(
            threadHandle,
            setEnvironmentVariableW,
            nameBaseAddress,
            valueBaseAddress,
            NULL
            );
#ifdef _WIN64
    }
#endif
    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = NtResumeThread(threadHandle, NULL); // Execute the pending APC (dmex)

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = NtWaitForSingleObject(threadHandle, FALSE, Timeout);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetThreadBasicInformation(threadHandle, &basicInformation);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = basicInformation.ExitStatus;

CleanupExit:

    if (threadHandle)
    {
        NtClose(threadHandle);
    }

    if (powerRequestHandle)
    {
        PhDestroyExecutionRequiredRequest(powerRequestHandle);
    }

    if (nameBaseAddress)
    {
        nameAllocationSize = 0;
        NtFreeVirtualMemory(
            ProcessHandle,
            &nameBaseAddress,
            &nameAllocationSize,
            MEM_RELEASE
            );
    }

    if (valueBaseAddress)
    {
        valueAllocationSize = 0;
        NtFreeVirtualMemory(
            ProcessHandle,
            &valueBaseAddress,
            &valueAllocationSize,
            MEM_RELEASE
            );
    }

    return status;
}

// based on https://www.drdobbs.com/a-safer-alternative-to-terminateprocess/184416547 (dmex)
NTSTATUS PhTerminateProcessAlternative(
    _In_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus,
    _In_opt_ ULONG Timeout
    )
{
    NTSTATUS status;
    PVOID rtlExitUserProcess = NULL;
    HANDLE powerRequestHandle = NULL;
    HANDLE threadHandle = NULL;
    PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;

    status = PhGetProcessRuntimeLibrary(
        ProcessHandle,
        &runtimeLibrary,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->NtdllFileName,
        "RtlExitUserProcess",
        &rtlExitUserProcess,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    if (WindowsVersion >= WINDOWS_8)
    {
        status = PhCreateExecutionRequiredRequest(ProcessHandle, &powerRequestHandle);

        if (!NT_SUCCESS(status))
            goto CleanupExit;
    }

    status = PhCreateUserThread(
        ProcessHandle,
        NULL,
        THREAD_ALL_ACCESS,
        0,
        0,
        0,
        0,
        rtlExitUserProcess,
        LongToPtr(ExitStatus),
        &threadHandle,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhWaitForSingleObject(threadHandle, Timeout);

CleanupExit:

    if (threadHandle)
    {
        NtClose(threadHandle);
    }

    if (powerRequestHandle)
    {
        PhDestroyExecutionRequiredRequest(powerRequestHandle);
    }

    return status;
}

/**
 * Retrieves a copy of the system DLL init block for the process.
 *
 * \param[in] ProcessHandle A handle to the process. The handle must have
 * PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ access.
 * \param[out] SystemDllInitBlock A buffer for a version-independent copy of LdrSystemDllInitBlock.
 *
 * \return Successful or errant status.
 */
NTSTATUS PhGetProcessSystemDllInitBlock(
    _In_ HANDLE ProcessHandle,
    _Out_ PPS_SYSTEM_DLL_INIT_BLOCK SystemDllInitBlock
    )
{
    NTSTATUS status;
    PS_SYSTEM_DLL_INIT_BLOCK systemDllInitBlock = { 0 };
    PVOID ldrSystemDllInitBlockAddress;
    ULONG expectedSize;

    // N.B. Aside from having three revisions, PS_SYSTEM_DLL_INIT_BLOCK
    // has different fields available on different OS versions. Determine
    // the maximum number of bytes we can read. (diversenok)

    if (WindowsVersion >= WINDOWS_11_24H2)
        expectedSize = sizeof(PS_SYSTEM_DLL_INIT_BLOCK_V3);
    else if (WindowsVersion >= PHNT_WINDOWS_10_20H1)
        expectedSize = RTL_SIZEOF_THROUGH_FIELD(PS_SYSTEM_DLL_INIT_BLOCK_V3, MitigationAuditOptionsMap);
    else if (WindowsVersion >= PHNT_WINDOWS_10_RS3)
        expectedSize = sizeof(PS_SYSTEM_DLL_INIT_BLOCK_V2);
    else if (WindowsVersion >= PHNT_WINDOWS_10_RS2)
        expectedSize = RTL_SIZEOF_THROUGH_FIELD(PS_SYSTEM_DLL_INIT_BLOCK_V2, Wow64CfgBitMapSize);
    else if (WindowsVersion >= PHNT_WINDOWS_10)
        expectedSize = sizeof(PS_SYSTEM_DLL_INIT_BLOCK_V1);
    else if (WindowsVersion >= PHNT_WINDOWS_8_1)
        expectedSize = RTL_SIZEOF_THROUGH_FIELD(PS_SYSTEM_DLL_INIT_BLOCK_V1, CfgBitMapSize);
    else if (WindowsVersion >= PHNT_WINDOWS_8)
        expectedSize = RTL_SIZEOF_THROUGH_FIELD(PS_SYSTEM_DLL_INIT_BLOCK_V1, MitigationOptions);
    else
        return STATUS_NOT_SUPPORTED;

    status = PhGetProcedureAddressRemoteZ(
        ProcessHandle,
        L"\\SystemRoot\\System32\\ntdll.dll",
        "LdrSystemDllInitBlock",
        &ldrSystemDllInitBlockAddress,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    status = NtReadVirtualMemory(
        ProcessHandle,
        ldrSystemDllInitBlockAddress,
        &systemDllInitBlock,
        expectedSize,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    if (systemDllInitBlock.Size > expectedSize)
        systemDllInitBlock.Size = expectedSize;

    status = PhCaptureSystemDllInitBlock(
        &systemDllInitBlock,
        SystemDllInitBlock
        );

    return status;
}

NTSTATUS PhGetProcessCodePage(
    _In_ HANDLE ProcessHandle,
    _Out_ PUSHORT ProcessCodePage
    )
{
    NTSTATUS status;
    USHORT codePage = 0;

    if (WindowsVersion >= WINDOWS_11)
    {
        PVOID pebBaseAddress;
#ifdef _WIN64
        BOOLEAN isWow64 = FALSE;

        PhGetProcessIsWow64(ProcessHandle, &isWow64);

        if (isWow64)
        {
            status = PhGetProcessPeb32(ProcessHandle, &pebBaseAddress);

            if (!NT_SUCCESS(status))
                goto CleanupExit;

            status = NtReadVirtualMemory(
                ProcessHandle,
                PTR_ADD_OFFSET(pebBaseAddress, UFIELD_OFFSET(PEB32, ActiveCodePage)),
                &codePage,
                sizeof(USHORT),
                NULL
                );
        }
        else
#endif
        {
            status = PhGetProcessPeb(ProcessHandle, &pebBaseAddress);

            if (!NT_SUCCESS(status))
                goto CleanupExit;

            status = NtReadVirtualMemory(
                ProcessHandle,
                PTR_ADD_OFFSET(pebBaseAddress, UFIELD_OFFSET(PEB, ActiveCodePage)),
                &codePage,
                sizeof(USHORT),
                NULL
                );
        }
    }
    else
    {
        PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;
        PVOID nlsAnsiCodePage;

        status = PhGetProcessRuntimeLibrary(
            ProcessHandle,
            &runtimeLibrary,
            NULL
            );

        if (!NT_SUCCESS(status))
            goto CleanupExit;

        status = PhGetProcedureAddressRemote(
            ProcessHandle,
            &runtimeLibrary->NtdllFileName,
            "NlsAnsiCodePage",
            &nlsAnsiCodePage,
            NULL
            );

        if (!NT_SUCCESS(status))
            goto CleanupExit;

        status = NtReadVirtualMemory(
            ProcessHandle,
            nlsAnsiCodePage,
            &codePage,
            sizeof(USHORT),
            NULL
            );
    }

    if (NT_SUCCESS(status))
    {
        *ProcessCodePage = codePage;
    }

CleanupExit:
    return status;
}

NTSTATUS PhGetProcessConsoleCodePage(
    _In_ HANDLE ProcessHandle,
    _In_ BOOLEAN ConsoleOutputCP,
    _Out_ PUSHORT ConsoleCodePage
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInformation;
    HANDLE threadHandle = NULL;
    HANDLE powerRequestHandle = NULL;
    PVOID getConsoleCP = NULL;
    PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;

    status = PhGetProcessRuntimeLibrary(
        ProcessHandle,
        &runtimeLibrary,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->Kernel32FileName,
        ConsoleOutputCP ? "GetConsoleOutputCP" : "GetConsoleCP",
        &getConsoleCP,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    if (WindowsVersion >= WINDOWS_8)
    {
        status = PhCreateExecutionRequiredRequest(ProcessHandle, &powerRequestHandle);

        if (!NT_SUCCESS(status))
            return status;
    }

    status = PhCreateUserThread(
        ProcessHandle,
        NULL,
        THREAD_ALL_ACCESS,
        0,
        0,
        0,
        0,
        getConsoleCP,
        NULL,
        &threadHandle,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhWaitForSingleObject(threadHandle, 5000);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetThreadBasicInformation(threadHandle, &basicInformation);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    *ConsoleCodePage = (USHORT)basicInformation.ExitStatus;

CleanupExit:
    if (threadHandle)
    {
        NtClose(threadHandle);
    }

    if (powerRequestHandle)
    {
        PhDestroyExecutionRequiredRequest(powerRequestHandle);
    }

    return status;
}

NTSTATUS PhFlushProcessHeapsRemote(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PLARGE_INTEGER Timeout
    )
{
    NTSTATUS status;
    THREAD_BASIC_INFORMATION basicInformation;
    PVOID rtlExitUserThread = NULL;
    PVOID rtlFlushHeaps = NULL;
    HANDLE threadHandle = NULL;
    HANDLE powerRequestHandle = NULL;
    PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;
#ifdef _WIN64
    BOOLEAN isWow64;
#endif

    status = PhGetProcessRuntimeLibrary(
        ProcessHandle,
        &runtimeLibrary,
#ifdef _WIN64
        &isWow64
#else
        NULL
#endif
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->NtdllFileName,
        "RtlExitUserThread",
        &rtlExitUserThread,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->NtdllFileName,
        "RtlFlushHeaps",
        &rtlFlushHeaps,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    if (WindowsVersion >= WINDOWS_8)
    {
        status = PhCreateExecutionRequiredRequest(ProcessHandle, &powerRequestHandle);

        if (!NT_SUCCESS(status))
            goto CleanupExit;
    }

    status = PhCreateUserThread(
        ProcessHandle,
        NULL,
        THREAD_ALL_ACCESS,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        0,
        0,
        0,
        rtlExitUserThread,
        LongToPtr(STATUS_SUCCESS),
        &threadHandle,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

#ifdef _WIN64
    if (isWow64)
    {
        status = RtlQueueApcWow64Thread(
            threadHandle,
            rtlFlushHeaps,
            NULL,
            NULL,
            NULL
            );
    }
    else
    {
#endif
        status = NtQueueApcThreadEx(
            threadHandle,
            QUEUE_USER_APC_SPECIAL_USER_APC,
            rtlFlushHeaps,
            NULL,
            NULL,
            NULL
            );
#ifdef _WIN64
    }
#endif
    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = NtResumeThread(threadHandle, NULL); // Execute the pending APC (dmex)

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = NtWaitForSingleObject(threadHandle, FALSE, Timeout);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetThreadBasicInformation(threadHandle, &basicInformation);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = basicInformation.ExitStatus;

CleanupExit:

    if (threadHandle)
    {
        NtClose(threadHandle);
    }

    if (powerRequestHandle)
    {
        PhDestroyExecutionRequiredRequest(powerRequestHandle);
    }

    return status;
}

/*
 * Invokes a procedure in the context of the owning thread for the window.
 *
 * \param WindowHandle The handle of the window.
 * \param ApcRoutine The procedure to be invoked.
 * \param ApcArgument1 The first argument to be passed to the procedure.
 * \param ApcArgument2 The second argument to be passed to the procedure.
 * \param ApcArgument3 The third argument to be passed to the procedure.
 *
 * \return The status of the operation.
 */
NTSTATUS PhInvokeWindowProcedureRemote(
    _In_ HWND WindowHandle,
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    )
{
    NTSTATUS status;
    HANDLE processHande = NULL;
    HANDLE threadHande = NULL;
    HANDLE powerHandle = NULL;
    CLIENT_ID clientId;

    // Get the client ID of the window.

    status = PhGetWindowClientId(WindowHandle, &clientId);

    if (!NT_SUCCESS(status))
        return status;

    // Open the process associated with the window.

    status = PhOpenProcessClientId(
        &processHande,
        PROCESS_ALL_ACCESS,
        &clientId
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    // Open the thread associated with the window.

    status = PhOpenThreadClientId(
        &threadHande,
        THREAD_ALL_ACCESS, // THREAD_ALERT
        &clientId
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    // Create an execution required request for the process (Windows 8 and above)

    if (WindowsVersion >= WINDOWS_8)
    {
        status = PhCreateExecutionRequiredRequest(processHande, &powerHandle);

        if (!NT_SUCCESS(status))
            goto CleanupExit;
    }

    // Queue a Special user-mode APC to execute within the context of the message loop.

    status = NtQueueApcThreadEx(
        threadHande,
        QUEUE_USER_APC_SPECIAL_USER_APC,
        ApcRoutine,
        ApcArgument1,
        ApcArgument2,
        ApcArgument3
        );

CleanupExit:
    if (threadHande)
        NtClose(threadHande);
    if (processHande)
        NtClose(processHande);
    if (powerHandle)
        PhDestroyExecutionRequiredRequest(powerHandle);

    return status;
}

/**
 * Destroys the specified window in a process.
 *
 * \param ProcessHandle A handle to a process. The handle must have PROCESS_SET_LIMITED_INFORMATION access.
 * \param WindowHandle A handle to the window to be destroyed.
 *
 * \return Successful or errant status.
 *
 * \remarks A thread cannot call DestroyWindow for a window created by a different thread,
 * unless we queue a special APC to the owner thread.
 */
NTSTATUS PhDestroyWindowRemote(
    _In_ HANDLE ProcessHandle,
    _In_ HWND WindowHandle
    )
{
    NTSTATUS status;
    PVOID destroyWindow = NULL;
    PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;

    status = PhGetProcessRuntimeLibrary(
        ProcessHandle,
        &runtimeLibrary,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->User32FileName,
        "DestroyWindow",
        &destroyWindow,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhInvokeWindowProcedureRemote(
        WindowHandle,
        destroyWindow,
        (PVOID)WindowHandle,
        NULL,
        NULL
        );

CleanupExit:
    return status;
}

NTSTATUS PhPostWindowQuitMessageRemote(
    _In_ HANDLE ProcessHandle,
    _In_ HWND WindowHandle
    )
{
    NTSTATUS status;
    PVOID postQuitMessage = NULL;
    PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;

    status = PhGetProcessRuntimeLibrary(
        ProcessHandle,
        &runtimeLibrary,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->User32FileName,
        "PostQuitMessage",
        &postQuitMessage,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhInvokeWindowProcedureRemote(
        WindowHandle,
        postQuitMessage,
        UlongToPtr(EXIT_SUCCESS),
        NULL,
        NULL
        );

CleanupExit:
    return status;
}

/// https://learn.microsoft.com/en-us/windows/win32/multimedia/obtaining-and-setting-timer-resolution
NTSTATUS PhSetProcessTimerResolutionRemote(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG Period
    )
{
    NTSTATUS status;
    PVOID rtlExitUserThread = NULL;
    PVOID timeBeginPeriod = NULL;
    HANDLE threadHandle = NULL;
    HANDLE powerRequestHandle = NULL;
    PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;
    LARGE_INTEGER timeout;
#ifdef _WIN64
    BOOLEAN isWow64;
#endif

    status = PhGetProcessRuntimeLibrary(
        ProcessHandle,
        &runtimeLibrary,
#ifdef _WIN64
        & isWow64
#else
        NULL
#endif
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->NtdllFileName,
        "RtlExitUserThread",
        &rtlExitUserThread,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->Kernel32FileName,
        "TimeBeginPeriod",
        &timeBeginPeriod,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    if (WindowsVersion >= WINDOWS_8)
    {
        status = PhCreateExecutionRequiredRequest(ProcessHandle, &powerRequestHandle);

        if (!NT_SUCCESS(status))
            goto CleanupExit;
    }

    status = PhCreateUserThread(
        ProcessHandle,
        NULL,
        THREAD_ALL_ACCESS,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        0,
        0,
        0,
        rtlExitUserThread,
        LongToPtr(STATUS_SUCCESS),
        &threadHandle,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

#ifdef _WIN64
    if (isWow64)
    {
        status = RtlQueueApcWow64Thread(
            threadHandle,
            timeBeginPeriod,
            UlongToPtr(Period),
            NULL,
            NULL
            );
    }
    else
    {
#endif
        status = NtQueueApcThread(
            threadHandle,
            timeBeginPeriod,
            UlongToPtr(Period),
            NULL,
            NULL
            );
#ifdef _WIN64
    }
#endif
    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = NtResumeThread(threadHandle, NULL);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = NtWaitForSingleObject(threadHandle, FALSE, PhTimeoutFromMilliseconds(&timeout, 5000));

    if (!NT_SUCCESS(status))
        goto CleanupExit;

CleanupExit:

    if (threadHandle)
    {
        NtClose(threadHandle);
    }

    if (powerRequestHandle)
    {
        PhDestroyExecutionRequiredRequest(powerRequestHandle);
    }

    return status;
}

NTSTATUS PhSetProcessTimerResolutionRemote2(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG Period
    )
{
    NTSTATUS status;
    PVOID rtlExitUserThread = NULL;
    PVOID timeBeginPeriod = NULL;
    HANDLE threadHandle = NULL;
    HANDLE powerRequestHandle = NULL;
    PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;
#ifdef _WIN64
    BOOLEAN isWow64;
#endif

    status = PhGetProcessRuntimeLibrary(
        ProcessHandle,
        &runtimeLibrary,
#ifdef _WIN64
        & isWow64
#else
        NULL
#endif
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->NtdllFileName,
        "RtlExitUserThread",
        &rtlExitUserThread,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->Kernel32FileName,
        "TimeBeginPeriod",
        &timeBeginPeriod,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    if (WindowsVersion >= WINDOWS_8)
    {
        status = PhCreateExecutionRequiredRequest(ProcessHandle, &powerRequestHandle);

        if (!NT_SUCCESS(status))
            goto CleanupExit;
    }

    status = PhCreateUserThread(
        ProcessHandle,
        NULL,
        THREAD_ALL_ACCESS,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        0,
        0,
        0,
        rtlExitUserThread,
        LongToPtr(STATUS_SUCCESS),
        &threadHandle,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

#ifdef _WIN64
    if (isWow64)
    {
        status = RtlQueueApcWow64Thread(
            threadHandle,
            timeBeginPeriod,
            UlongToPtr(Period),
            NULL,
            NULL
            );
    }
    else
    {
#endif
        status = NtQueueApcThread(
            threadHandle,
            timeBeginPeriod,
            UlongToPtr(Period),
            NULL,
            NULL
            );
#ifdef _WIN64
    }
#endif
    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = NtResumeThread(threadHandle, NULL);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhWaitForSingleObject(threadHandle, 5000);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

CleanupExit:

    if (threadHandle)
    {
        NtClose(threadHandle);
    }

    if (powerRequestHandle)
    {
        PhDestroyExecutionRequiredRequest(powerRequestHandle);
    }

    return status;
}

NTSTATUS PhSetHandleInformationRemote(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE RemoteHandle,
    _In_ ULONG Mask,
    _In_ ULONG Flags
    )
{
    NTSTATUS status;
    PVOID rtlExitUserThread = NULL;
    PVOID setHandleInformation = NULL;
    HANDLE threadHandle = NULL;
    HANDLE powerRequestHandle = NULL;
    PPH_PROCESS_RUNTIME_LIBRARY runtimeLibrary;
    THREAD_BASIC_INFORMATION basicInformation;
#ifdef _WIN64
    BOOLEAN isWow64;
#endif

    status = PhGetProcessRuntimeLibrary(
        ProcessHandle,
        &runtimeLibrary,
#ifdef _WIN64
        & isWow64
#else
        NULL
#endif
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->NtdllFileName,
        "RtlExitUserThread",
        &rtlExitUserThread,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetProcedureAddressRemote(
        ProcessHandle,
        &runtimeLibrary->Kernel32FileName,
        "SetHandleInformation",
        &setHandleInformation,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    if (WindowsVersion >= WINDOWS_8)
    {
        status = PhCreateExecutionRequiredRequest(ProcessHandle, &powerRequestHandle);

        if (!NT_SUCCESS(status))
            goto CleanupExit;
    }

    status = PhCreateUserThread(
        ProcessHandle,
        NULL,
        THREAD_ALL_ACCESS,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        0,
        0,
        0,
        rtlExitUserThread,
        LongToPtr(STATUS_SUCCESS),
        &threadHandle,
        NULL
        );

    if (!NT_SUCCESS(status))
        goto CleanupExit;

#ifdef _WIN64
    if (isWow64)
    {
        status = RtlQueueApcWow64Thread(
            threadHandle,
            setHandleInformation,
            RemoteHandle,
            UlongToPtr(Mask),
            UlongToPtr(Flags)
            );
    }
    else
    {
#endif
        status = NtQueueApcThread(
            threadHandle,
            setHandleInformation,
            RemoteHandle,
            UlongToPtr(Mask),
            UlongToPtr(Flags)
            );
#ifdef _WIN64
    }
#endif
    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = NtResumeThread(threadHandle, NULL);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhWaitForSingleObject(threadHandle, 5000);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = PhGetThreadBasicInformation(threadHandle, &basicInformation);

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    status = basicInformation.ExitStatus;

CleanupExit:

    if (threadHandle)
    {
        NtClose(threadHandle);
    }

    if (powerRequestHandle)
    {
        PhDestroyExecutionRequiredRequest(powerRequestHandle);
    }

    return status;
}

//#include <ntddk.h>
#include "pch.h"
#include "ApcInject.h"
#include "AutoLock.h"
#include <ntdef.h>
#include <ntimage.h>
#include "ApcApi.h"
// 两个未公开函数导出
extern "C" NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS Process);
extern "C" NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS * Process);

INJ_SYSTEM_DLL_DESCRIPTOR InjpSystemDlls[] = {
	{ RTL_CONSTANT_STRING(L"\\SysWow64\\ntdll.dll"),    INJ_SYSWOW64_NTDLL_LOADED    },
	{ RTL_CONSTANT_STRING(L"\\System32\\ntdll.dll"),    INJ_SYSTEM32_NTDLL_LOADED    },
	{ RTL_CONSTANT_STRING(L"\\System32\\wow64.dll"),    INJ_SYSTEM32_WOW64_LOADED    },
	{ RTL_CONSTANT_STRING(L"\\System32\\wow64win.dll"), INJ_SYSTEM32_WOW64WIN_LOADED },
	{ RTL_CONSTANT_STRING(L"\\System32\\wow64cpu.dll"), INJ_SYSTEM32_WOW64CPU_LOADED },
	{ RTL_CONSTANT_STRING(L"\\System32\\wowarmhw.dll"), INJ_SYSTEM32_WOWARMHW_LOADED },
	{ RTL_CONSTANT_STRING(L"\\System32\\xtajit.dll"),   INJ_SYSTEM32_XTAJIT_LOADED   },
};

ANSI_STRING LdrLoadDllRoutineName = RTL_CONSTANT_STRING("LdrLoadDll");



Globals g_Globals;

void PushItem(LIST_ENTRY* entry)
{
	AutoLock<FastMutex> lock(g_Globals.Mutex);
	if (g_Globals.ItemCount > 30)
	{
		// 最多30个
		auto head = RemoveHeadList(&g_Globals.ItemsHead);
		g_Globals.ItemCount--;
		auto item = CONTAINING_RECORD(head, FullItem<ProcessInfo>, Entry);
		ExFreePool(item);
	}


	InsertTailList(&g_Globals.ItemsHead, entry);
	g_Globals.ItemCount++;
	
}

FullItem<ProcessInfo>* FindItem(HANDLE ProcessId)
{
	//AutoLock<FastMutex> lock(g_Globals.Mutex);
	if (g_Globals.ItemCount <= 0)
		return NULL;
	auto head = g_Globals.ItemsHead.Flink;
	//DbgPrint("TEST: 当前g_Globals.ItemCount:%d", g_Globals.ItemCount);

	for (int n = 0; n < g_Globals.ItemCount; n++)
	{

		FullItem<ProcessInfo>* item = CONTAINING_RECORD(head, FullItem<ProcessInfo>, Entry);
		//DbgPrint("TEST: FindItem item->Data.InjectedThreadID:%ld,InjectedThreadID:%ld", item->Data.InjectedThreadID, InjectedThreadID);
		if (item->Data.ProcessId == ProcessId)
		{
			return item;
		}
		else
		{
			head = head->Flink;
		}
	}
	return NULL;
}


BOOLEAN DeleteItem(HANDLE ProcessId)
{
	FullItem<ProcessInfo>* pProcessInfo = FindItem(ProcessId);
	if (pProcessInfo != NULL)
	{
		RemoveEntryList(&pProcessInfo->Entry);
		g_Globals.ItemCount--;

		ExFreePool(pProcessInfo);
		return TRUE;
	}
	return FALSE;
}

VOID
ProcessNotifierEx(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{

	if (CreateInfo != NULL)
	{


		CHAR* ProcessName = PsGetProcessImageFileName(Process);
		ANSI_STRING ANSI_ProcessName = RTL_CONSTANT_STRING(ProcessName);
		//RtlInitAnsiString(&ANSI_ProcessName, (PCSZ)ProcessName);
		if (ProcessName && RtlCompareMemory((PCSZ)ProcessName, INJECTEXE, sizeof(INJECTEXE)) == sizeof(INJECTEXE))
		{

			FullItem<ProcessInfo>* info = (FullItem<ProcessInfo>*)ExAllocatePoolWithTag(PagedPool, sizeof(FullItem<ProcessInfo>), DRIVER_TAG);
			if (info != NULL)
			{
				//AutoLock<FastMutex> lock(g_Globals.Mutex);
				RtlZeroMemory(info, sizeof(FullItem<ProcessInfo>));
				info->Data.ProcessId = ProcessId;
				PushItem(&info->Entry);
			}

		}

	}
	else
	{
		//strcpy_s(ProcName, 16, PsGetProcessImageFileName(Process));
		AutoLock<FastMutex> lock(g_Globals.Mutex);
		//DbgPrint(" 进程[ %s ] 退出了, 程序被关闭", PsGetProcessImageFileName(Process));
		KdPrint((DRIVER_PREFIX " Process[ %s ] Exit\r\n", PsGetProcessImageFileName(Process)));
		DeleteItem(ProcessId);
	}
}
BOOLEAN
NTAPI
CmpUnicodeString(
	_In_ PUNICODE_STRING String1,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN CaseInSensitive
)
{
	//
	// RtlSuffixUnicodeString is not exported by ntoskrnl until Win10.
	//

	return String2->Length >= String1->Length &&
		RtlCompareUnicodeStrings(String2->Buffer + (String2->Length - String1->Length) / sizeof(WCHAR),
			String1->Length / sizeof(WCHAR),
			String1->Buffer,
			String1->Length / sizeof(WCHAR),
			CaseInSensitive) == 0;

}


extern "C"
NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
	_In_ PVOID BaseOfImage,
	_In_ BOOLEAN MappedAsImage,
	_In_ USHORT DirectoryEntry,
	_Out_ PULONG Size
);
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
PVOID
NTAPI
RtlxFindExportedRoutineByName(
	_In_ PVOID DllBase,
	_In_ PUNICODE_STRING ExportName
)
{
	//
	// RtlFindExportedRoutineByName is not exported by ntoskrnl until Win10.
	// Following code is borrowed from ReactOS.
	//

	PULONG NameTable;
	PUSHORT OrdinalTable;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	LONG Low = 0, Mid = 0, High, Ret;
	USHORT Ordinal;
	PVOID Function;
	ULONG ExportSize;
	PULONG ExportTable;

	//
	// Get the export directory.
	//

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		&ExportSize);

	if (!ExportDirectory)
	{
		return NULL;
	}

	//
	// Setup name tables.
	//

	NameTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
	OrdinalTable = (PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);

	//
	// Do a binary search.
	//

	High = ExportDirectory->NumberOfNames - 1;
	while (High >= Low)
	{
		//
		// Get new middle value.
		//

		Mid = (Low + High) >> 1;

		//
		// Compare name.
		//

		Ret = strcmp((PCSZ)ExportName->Buffer, (PCHAR)DllBase + NameTable[Mid]);

		if (Ret < 0)
		{
			//
			// Update high.
			//
			High = Mid - 1;
		}
		else if (Ret > 0)
		{
			//
			// Update low.
			//
			Low = Mid + 1;
		}
		else
		{
			//
			// We got it.
			//
			break;
		}
	}

	//
	// Check if we couldn't find it.
	//

	if (High < Low)
	{
		return NULL;
	}

	//
	// Otherwise, this is the ordinal.
	//

	Ordinal = OrdinalTable[Mid];

	//
	// Validate the ordinal.
	//

	if (Ordinal >= ExportDirectory->NumberOfFunctions)
	{
		return NULL;
	}

	//
	// Resolve the address and write it.
	//

	ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
	Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);

	//
	// We found it!
	//

	NT_ASSERT(
		(Function < (PVOID)ExportDirectory) ||
		(Function > (PVOID)((ULONG_PTR)ExportDirectory + ExportSize))
	);

	return Function;
}

#if(NTDDI_VERSION > NTDDI_WIN7)
BOOLEAN InjIsWindows7 = TRUE;
#else
BOOLEAN InjIsWindows7 = FALSE;
#endif
extern "C"
NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(
	_In_ PEPROCESS Process
);


#define INJ_CONFIG_SUPPORTS_WOW64
BOOLEAN
NTAPI
InjCanInject(
	_In_ ProcessInfo* ProcessInfo
)
{
	//
	// DLLs that need to be loaded in the native process
	// (i.e.: x64 process on x64 Windows, x86 process on
	// x86 Windows) before we can safely load our DLL.
	//

	ULONG RequiredDlls = INJ_SYSTEM32_NTDLL_LOADED;
#if _WIN64 || __amd64__		
#if defined(INJ_CONFIG_SUPPORTS_WOW64)

	if (PsGetProcessWow64Process(PsGetCurrentProcess()))
	{
		//
		// DLLs that need to be loaded in the Wow64 process
		// before we can safely load our DLL.
		//

		RequiredDlls |= INJ_SYSTEM32_NTDLL_LOADED;
		RequiredDlls |= INJ_SYSTEM32_WOW64_LOADED;
		RequiredDlls |= INJ_SYSTEM32_WOW64WIN_LOADED;

#    if  defined (_M_AMD64)

		RequiredDlls |= INJ_SYSTEM32_WOW64CPU_LOADED;
		RequiredDlls |= INJ_SYSWOW64_NTDLL_LOADED;

#    endif

	}
#endif
#endif

	return (ProcessInfo->LoadedDlls & RequiredDlls) == RequiredDlls;
}


VOID
NTAPI
InjpInjectApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	//
	// Common kernel routine for both user-mode and
	// kernel-mode APCs queued by the InjpQueueApc
	// function.  Just release the memory of the APC
	// structure and return back.
	//

	ExFreePoolWithTag(Apc, INJ_MEMORY_TAG);
}


NTSTATUS
NTAPI
InjpQueueApc(
	_In_ KPROCESSOR_MODE ApcMode,
	_In_ PKNORMAL_ROUTINE NormalRoutine,
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
)
{
	//
	// Allocate memory for the KAPC structure.
	//

#pragma prefast(push)
#pragma prefast(disable:6014)

	PKAPC Apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPoolNx,
		sizeof(KAPC),
		INJ_MEMORY_TAG);

#pragma prefast(pop)

	if (!Apc)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Initialize and queue the APC.
	//

	KeInitializeApc(Apc,                                  // Apc
		PsGetCurrentThread(),                 // Thread
		OriginalApcEnvironment,               // Environment
		&InjpInjectApcKernelRoutine,          // KernelRoutine
		NULL,                                 // RundownRoutine
		NormalRoutine,                        // NormalRoutine
		ApcMode,                              // ApcMode
		NormalContext);                       // NormalContext

	BOOLEAN Inserted = KeInsertQueueApc(Apc,              // Apc
		SystemArgument1,  // SystemArgument1
		SystemArgument2,  // SystemArgument2
		0);               // Increment

	if (!Inserted)
	{
		ExFreePoolWithTag(Apc, INJ_MEMORY_TAG);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
InjpInjectX32(
	_In_ ProcessInfo* ProcessInfo,
	_In_ HANDLE SectionHandle,
	_In_ SIZE_T SectionSize
)
{
	NTSTATUS Status;
	UNICODE_STRING  InjDllPath = { 0 };
	RtlInitUnicodeString(&InjDllPath, DLLX32);// = RTL_CONSTANT_STRING(L"D:\\WORKSPACE\\DRIP_1.10.0\\dc_client_win\\dc_agent\\bin\\x64\\Debug\\{VersionNameFolder}\\DcCmdHook.dll");

	// First, map this section with read-write access.
	//

	PVOID SectionMemoryAddress = NULL;
	do
	{
		Status = ZwMapViewOfSection(SectionHandle,
			ZwCurrentProcess(),
			&SectionMemoryAddress,
			0,
			SectionSize,
			NULL,
			&SectionSize,
			ViewUnmap,
			0,
			PAGE_READWRITE);

		if (!NT_SUCCESS(Status))
		{
			KdPrint((DRIVER_PREFIX "ZwMapViewOfSection : %x\r\n", Status));
			break;
		}

		//
		// Code of the APC routine (ApcNormalRoutine defined in the
		// "shellcode" above) starts at the SectionMemoryAddress.
		// Copy the shellcode to the allocated memory.
		//
		UCHAR InjpThunkX86[] = {              //
			0x83, 0xec, 0x08,                   // sub    esp,0x8
			0x0f, 0xb7, 0x44, 0x24, 0x14,       // movzx  eax,[esp + 0x14]
			0x66, 0x89, 0x04, 0x24,             // mov    [esp],ax
			0x66, 0x89, 0x44, 0x24, 0x02,       // mov    [esp + 0x2],ax
			0x8b, 0x44, 0x24, 0x10,             // mov    eax,[esp + 0x10]
			0x89, 0x44, 0x24, 0x04,             // mov    [esp + 0x4],eax
			0x8d, 0x44, 0x24, 0x14,             // lea    eax,[esp + 0x14]
			0x50,                               // push   eax
			0x8d, 0x44, 0x24, 0x04,             // lea    eax,[esp + 0x4]
			0x50,                               // push   eax
			0x6a, 0x00,                         // push   0x0
			0x6a, 0x00,                         // push   0x0
			0xff, 0x54, 0x24, 0x1c,             // call   [esp + 0x1c]
			0x83, 0xc4, 0x08,                   // add    esp,0x8
			0xc2, 0x0c, 0x00,                   // ret    0xc
		};                                    //

		PVOID ApcRoutineAddress = SectionMemoryAddress;
		RtlCopyMemory(ApcRoutineAddress,
			InjpThunkX86,
			sizeof(InjpThunkX86));

		//
		// Fill the data of the ApcContext.
		//

		PWCHAR DllPath = (PWCHAR)((PUCHAR)SectionMemoryAddress + sizeof(InjpThunkX86));
		RtlCopyMemory(DllPath,
			InjDllPath.Buffer,
			InjDllPath.Length);

		//
		// Unmap the section and map it again, but now
		// with read-execute (no write) access.
		//

		ZwUnmapViewOfSection(ZwCurrentProcess(), SectionMemoryAddress);

		SectionMemoryAddress = NULL;
		Status = ZwMapViewOfSection(SectionHandle,
			ZwCurrentProcess(),
			&SectionMemoryAddress,
			0,
			PAGE_SIZE,
			NULL,
			&SectionSize,
			ViewUnmap,
			0,
			PAGE_EXECUTE_READ);

		if (!NT_SUCCESS(Status))
		{
			KdPrint((DRIVER_PREFIX "ZwMapViewOfSection : %x\r\n", Status));
			break;
		}

		//
		// Reassign remapped address.
		//

		ApcRoutineAddress = SectionMemoryAddress;
		DllPath = (PWCHAR)((PUCHAR)SectionMemoryAddress + sizeof(InjpThunkX86));

		PVOID ApcContext = (PVOID)ProcessInfo->LdrLoadDllRoutineAddress;
		PVOID ApcArgument1 = (PVOID)DllPath;
		PVOID ApcArgument2 = (PVOID)InjDllPath.Length;

#if _WIN64 || __amd64__
#if defined(INJ_CONFIG_SUPPORTS_WOW64)

		if (PsGetProcessWow64Process(PsGetCurrentProcess()))
		{
			//
			// PsWrapApcWow64Thread essentially assigns wow64.dll!Wow64ApcRoutine
			// to the NormalRoutine.  This Wow64ApcRoutine (which is 64-bit code)
			// in turn calls KiUserApcDispatcher (in 32-bit ntdll.dll) which finally
			// calls our provided ApcRoutine.
			//

			PsWrapApcWow64Thread(&ApcContext, &ApcRoutineAddress);
		}

#endif
#endif

		PKNORMAL_ROUTINE ApcRoutine = (PKNORMAL_ROUTINE)(ULONG_PTR)ApcRoutineAddress;

		Status = InjpQueueApc(UserMode,
			ApcRoutine,
			ApcContext,
			ApcArgument1,
			ApcArgument2);

		if (!NT_SUCCESS(Status))
		{
			//
			// If injection failed for some reason, unmap the section.
			//
			KdPrint((DRIVER_PREFIX "InjpQueueApc : %x\r\n", Status));
			ZwUnmapViewOfSection(ZwCurrentProcess(), SectionMemoryAddress);
			break;
		}
	} while (false);
	

Exit:
	return Status;
}


NTSTATUS
NTAPI
InjpInjectX64(
	_In_ ProcessInfo* ProcessInfo,
	_In_ HANDLE SectionHandle,
	_In_ SIZE_T SectionSize
)
{

	NT_ASSERT(ProcessInfo->LdrLoadDllRoutineAddress);
	//DbgBreakPoint();
	NTSTATUS Status;
	UNICODE_STRING  InjDllPath = { 0 };
	RtlInitUnicodeString(&InjDllPath, DLLX64);// = RTL_CONSTANT_STRING(L"D:\\WORKSPACE\\DRIP_1.10.0\\dc_client_win\\dc_agent\\bin\\x64\\Debug\\{VersionNameFolder}\\DcCmdHook.dll");
	InjDllPath.MaximumLength = sizeof(WCHAR) * MAX_PATH;
	PVOID SectionMemoryAddress = NULL;
	do
	{
		Status = ZwMapViewOfSection(SectionHandle,
			ZwCurrentProcess(),
			&SectionMemoryAddress,
			0,
			PAGE_SIZE,
			NULL,
			&SectionSize,
			ViewUnmap,
			0,
			PAGE_READWRITE);

		if (!NT_SUCCESS(Status))
		{
			break;
		}

		//
		// Create the UNICODE_STRING structure and fill out the
		// full path of the DLL.
		//

		PUNICODE_STRING DllPath = (PUNICODE_STRING)(SectionMemoryAddress);
		PWCHAR DllPathBuffer = (PWCHAR)((PUCHAR)DllPath + sizeof(UNICODE_STRING));

		RtlCopyMemory(DllPathBuffer,
			InjDllPath.Buffer,
			InjDllPath.Length);

#pragma prefast(push)
#pragma prefast(disable:6386)
#pragma prefast(disable:6387)

		RtlInitUnicodeString(DllPath, DllPathBuffer);





		Status = InjpQueueApc(UserMode,
			(PKNORMAL_ROUTINE)(ULONG_PTR)ProcessInfo->LdrLoadDllRoutineAddress,
			NULL,     // Translates to 1st param. of LdrLoadDll (SearchPath)
			NULL,     // Translates to 2nd param. of LdrLoadDll (DllCharacteristics)
			DllPath); // Translates to 3rd param. of LdrLoadDll (DllName)

#pragma prefast(pop)
	} while (false);



Exit:
	return Status;
}


NTSTATUS
NTAPI
NormalInject(
	_In_ ProcessInfo* ProcessInfo
)
{
	NTSTATUS Status;

	//
	// Create memory space for injection-specific data,
	// such as path to the to-be-injected DLL.  Memory
	// of this section will be eventually mapped to the
	// injected process.
	//
	// Note that this memory is created using sections
	// instead of ZwAllocateVirtualMemory, mainly because
	// function ZwProtectVirtualMemory is not exported
	// by ntoskrnl.exe until Windows 8.1.  In case of
	// sections, the effect of memory protection change
	// is achieved by remaping the section with different
	// protection type.
	//

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	HANDLE SectionHandle;
	SIZE_T SectionSize = PAGE_SIZE;
	LARGE_INTEGER MaximumSize;
	MaximumSize.QuadPart = SectionSize;
	Status = ZwCreateSection(&SectionHandle,
		GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
		&ObjectAttributes,
		&MaximumSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}


	//InjpInject
	if (PsGetProcessWow64Process(PsGetCurrentProcess()))
	{
		Status = InjpInjectX32(ProcessInfo, SectionHandle, SectionSize);
	}
	else
	{
		Status = InjpInjectX64(ProcessInfo,
			SectionHandle,
			SectionSize);
	}

	return Status;
}





void ImageNotifier(
	PUNICODE_STRING FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo
)
{
	PEPROCESS pEProcess = NULL;

	do
	{
		AutoLock<FastMutex> lock(g_Globals.Mutex);
		auto Item = FindItem(ProcessId);
		if (Item == NULL)
			break;
		if (!InjCanInject(&Item->Data))
		{
			for (ULONG Index = 0; Index < RTL_NUMBER_OF(InjpSystemDlls); Index += 1)
			{
				PUNICODE_STRING SystemDllPath = &InjpSystemDlls[Index].DllPath;
				if (CmpUnicodeString(SystemDllPath, FullImageName, TRUE))
				{
					PVOID LdrLoadDllRoutineAddress = RtlxFindExportedRoutineByName(ImageInfo->ImageBase,
						(PUNICODE_STRING)&LdrLoadDllRoutineName);
					ULONG DllFlag = InjpSystemDlls[Index].Flag;
					Item->Data.LoadedDlls |= DllFlag;
					switch (DllFlag)
					{
						//
						// In case of "thunk method", capture address of the LdrLoadDll
						// routine from the ntdll.dll (which is of the same architecture
						// as the process).
						//

					case INJ_SYSARM32_NTDLL_LOADED:
					case INJ_SYCHPE32_NTDLL_LOADED:
					case INJ_SYSWOW64_NTDLL_LOADED:
						//DbgBreakPoint();
						Item->Data.LdrLoadDllRoutineAddress = LdrLoadDllRoutineAddress;

						break;

						//
						// For "thunkless method", capture address of the LdrLoadDll
						// routine from the native ntdll.dll.
						//

					case INJ_SYSTEM32_NTDLL_LOADED:
						Item->Data.LdrLoadDllRoutineAddress = LdrLoadDllRoutineAddress;
						break;

					default:
						break;
					}
				}

			}
		}
		else
		{

			NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &pEProcess);
			if (!NT_SUCCESS(status))
			{
				KdPrint((DRIVER_PREFIX "PsLookupProcessByProcessId ERROR![% x]\r\n", status));
				break;
			}
			if (InjIsWindows7 &&
				PsGetProcessWow64Process(pEProcess))
			{
				//
				// On Windows 7, if we're injecting DLL into Wow64 process using
				// the "thunk method", we have additionaly postpone the load after
				// these system DLLs.
				//
				// This is because on Windows 7, these DLLs are loaded as part of
				// the wow64!ProcessInit routine, therefore the Wow64 subsystem
				// is not fully initialized to execute our injected Wow64ApcRoutine.
				//

				UNICODE_STRING System32Kernel32Path = RTL_CONSTANT_STRING(L"\\System32\\kernel32.dll");
				UNICODE_STRING SysWOW64Kernel32Path = RTL_CONSTANT_STRING(L"\\SysWOW64\\kernel32.dll");
				UNICODE_STRING System32User32Path = RTL_CONSTANT_STRING(L"\\System32\\user32.dll");
				UNICODE_STRING SysWOW64User32Path = RTL_CONSTANT_STRING(L"\\SysWOW64\\user32.dll");

				if (CmpUnicodeString(&System32Kernel32Path, FullImageName, TRUE) ||
					CmpUnicodeString(&SysWOW64Kernel32Path, FullImageName, TRUE) ||
					CmpUnicodeString(&System32User32Path, FullImageName, TRUE) ||
					CmpUnicodeString(&SysWOW64User32Path, FullImageName, TRUE))
				{
					//DbgPrint("[injlib]: Postponing injection (%wZ)\n", FullImageName);
					KdPrint((DRIVER_PREFIX "[injlib]: Postponing injection (%wZ)\n\r\n", FullImageName));
					break;
				}

			}
			status = NormalInject(&Item->Data);

			if (NT_SUCCESS(status))
			{
				DeleteItem(&Item->Data);
			}
		}
	} while (false);

	if (pEProcess)
	{
		ObDereferenceObject(pEProcess);
		pEProcess = NULL;
	}

	return;
}
extern "C"
VOID UnDriver(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;

	status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifierEx, TRUE);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "UnloadProcessNotifyRoutine ERROR![% x]\r\n", status));
	}
	status = PsRemoveLoadImageNotifyRoutine(ImageNotifier);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "PsRemoveLoadImageNotifyRoutine ERROR![% x]\r\n", status));
	}
}

extern "C"
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = UnDriver;
	g_Globals.Mutex.Init();
	g_Globals.ItemCount = 0;
	InitializeListHead(&g_Globals.ItemsHead);

	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifierEx, FALSE);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "CreateProcessNotifyRoutine ERROR![% x]\r\n", status));
	}

	status = PsSetLoadImageNotifyRoutine(ImageNotifier);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX "LoadImageNotifyRoutine ERROR![% x]\r\n", status));
	}

	return status;
}
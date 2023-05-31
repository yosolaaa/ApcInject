#pragma once
//#include <ntdef.h>
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <minwindef.h>
#define x86											FALSE
#define x64											TRUE

#define DRIVER_PREFIX "yosolaaa: "
#define DRIVER_TAG 'yoso'
#define INJECTEXE "cmd.exe"

#define INJ_MEMORY_TAG ' jnI'


#define DLLX32	L"C:\\Users\\WDKRemoteUser\\Desktop\\Shell32.dll"
#define DLLX64	L"C:\\Users\\WDKRemoteUser\\Desktop\\Shell64.dll"
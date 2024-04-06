#pragma once

#include <Windows.h>

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

EXTERN_C NTSTATUS SysFuncAlloc(
  IN HANDLE           ProcessHandle,    // Process handle in where to allocate memory
  IN OUT PVOID        *BaseAddress,     // The returned allocated memory's base address
  IN ULONG_PTR        ZeroBits,         // Always set to '0'
  IN OUT PSIZE_T      RegionSize,       // Size of memory to allocate
  IN ULONG            AllocationType,   // MEM_COMMIT | MEM_RESERVE
  IN ULONG            Protect           // Page protection 
);

EXTERN_C NTSTATUS SysFuncThread(
    OUT PHANDLE                 ThreadHandle,         // Pointer to a HANDLE variable that recieves the created thread's handle
    IN 	ACCESS_MASK             DesiredAccess,        // Thread's access rights (set to THREAD_ALL_ACCESS - 0x1FFFFF)  
    IN 	POBJECT_ATTRIBUTES      ObjectAttributes,     // Pointer to OBJECT_ATTRIBUTES structure (set to NULL)
    IN 	HANDLE                  ProcessHandle,        // Handle to the process in which the thread is to be created.
    IN 	PVOID                   StartRoutine,         // Base address of the application-defined function to be executed
    IN 	PVOID                   Argument,             // Pointer to a variable to be passed to the thread function (set to NULL)
    IN 	ULONG                   CreateFlags,          // The flags that control the creation of the thread (set to NULL)
    IN 	SIZE_T                  ZeroBits,             // Set to NULL
    IN 	SIZE_T                  StackSize,            // Set to NULL
    IN 	SIZE_T                  MaximumStackSize,     // Set to NULL
    IN 	PPS_ATTRIBUTE_LIST      AttributeList         // Pointer to PS_ATTRIBUTE_LIST structure (set to NULL)
);
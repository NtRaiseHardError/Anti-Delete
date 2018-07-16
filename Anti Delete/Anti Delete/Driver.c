#include <fltKernel.h>

#define DEBUG
#ifdef DEBUG
#define DBG_PRINT(_fmt, ...) DbgPrint(_fmt, __VA_ARGS__)
#else
#define DBG_PRINT(_fmt, ...) { NOTHING; }
#endif // !DEBUG


DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS PreAntiDelete(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

// The callbacks array defines what IRPs we want to process.
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE, 0, PreAntiDelete, NULL },				// DELETE_ON_CLOSE creation flag.
	{ IRP_MJ_SET_INFORMATION, 0, PreAntiDelete, NULL },		// FileInformationClass == FileDispositionInformation(Ex).
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),				// Size
	FLT_REGISTRATION_VERSION,				// Version
	0,										// Flags
	NULL,									// ContextRegistration
	Callbacks,								// OperationRegistration
	Unload,									// FilterUnloadCallback
	NULL,									// InstanceSetupCallback
	NULL,									// InstanceQueryTeardownCallback
	NULL,									// InstanceTeardownStartCallback
	NULL,									// InstanceTeardownCompleteCallback
	NULL,									// GenerateFileNameCallback
	NULL,									// NormalizeNameComponentCallback
	NULL									// NormalizeContextCleanupCallback
};

PFLT_FILTER Filter;
static UNICODE_STRING ProtectedExtention = RTL_CONSTANT_STRING(L"PROTECTED");

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	// We can use this to load some configuration settings.
	UNREFERENCED_PARAMETER(RegistryPath);

	DBG_PRINT("DriverEntry called.\n");

	// Register the minifilter with the filter manager.
	NTSTATUS status = FltRegisterFilter(DriverObject, &FilterRegistration, &Filter);
	if (!NT_SUCCESS(status)) {
		DBG_PRINT("Failed to register filter: <0x%08x>.\n", status);
		return status;
	}
	
	// Start filtering I/O.
	status = FltStartFiltering(Filter);
	if (!NT_SUCCESS(status)) {
		DBG_PRINT("Failed to start filter: <0x%08x>.\n", status);
		// If we fail, we need to unregister the minifilter.
		FltUnregisterFilter(Filter);
	}

	return status;
}

/*
 * This is the driver unload routine used by the filter manager.
 * When the driver is requested to unload, it will call this function
 * and perform the necessary cleanups.
 */
NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);

	DBG_PRINT("Unload called.\n");

	// Unregister the minifilter.
	FltUnregisterFilter(Filter);

	return STATUS_SUCCESS;
}

/*
 * This routine is called every time I/O is requested for:
 * - file creates (IRP_MJ_CREATE) such as ZwCreateFile and 
 * - file metadata sets on files or file handles 
 *   (IRP_MJ_SET_INFORMATION) such as ZwSetInformation.
 *
 * This is a pre-operation callback routine which means that the
 * IRP passes through this function on the way down the driver stack
 * to the respective device or driver to be handled.
 */
FLT_PREOP_CALLBACK_STATUS PreAntiDelete(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
	UNREFERENCED_PARAMETER(CompletionContext);

	/* 
	 * This pre-operation callback code should be running at 
	 * IRQL <= APC_LEVEL as stated in the docs:
	 * https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-callback-routines
	 * and both ZwCreateFile and ZwSetInformaitonFile are also run at 
	 * IRQL == PASSIVE_LEVEL:
	 * - ZwCreateFile: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-ntcreatefile#requirements
	 * - ZwSetInformationFile: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-ntsetinformationfile#requirements
	 */
	PAGED_CODE();

	/*
	 * By default, we don't want to call the post-operation routine
	 * because there's no need to further process it and also
	 * because there is none.
	 */
	FLT_PREOP_CALLBACK_STATUS ret = FLT_PREOP_SUCCESS_NO_CALLBACK;

	// We don't care about directories.
	BOOLEAN IsDirectory;
	NTSTATUS status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &IsDirectory);
	if (NT_SUCCESS(status)) {
		if (IsDirectory == TRUE) {
			return ret;
		}
	}

	/*
	 * We don't want anything that doesn't have the DELETE_ON_CLOSE 
	 * flag.
	 */
	if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
		if (!FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
			return ret;
		}
	}

	/*
	 * We don't want anything that doesn't have either 
	 * FileDispositionInformation or FileDispositionInformationEx or 
	 * file renames (which can just simply rename the extension).
	 */
	if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
		switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
			case FileRenameInformation:
			case FileRenameInformationEx:
			case FileDispositionInformation:
			case FileDispositionInformationEx:
			case FileRenameInformationBypassAccessCheck:
			case FileRenameInformationExBypassAccessCheck:
			case FileShortNameInformation:
				break;
			default:
				return ret;
		}
	}

	/*
	 * Here we can check if we want to allow a specific process to fall 
	 * through the checks, e.g. our own application.
	 * Since this is a PASSIVE_LEVEL operation, we can assume(?) that 
	 * the thread context is the thread that requested the I/O. We can  
	 * check the current thread and compare the EPROCESS of the 
	 * authenticated application like so:
	 *
	 * if (IoThreadToProcess(Data->Thread) == UserProcess) {
	 *     return FLT_PREOP_SUCCESS_NO_CALLBACK;
	 * }
	 *
	 * Of course, we would need to find and save the EPROCESS of the 
	 * application somewhere first. Something like a communication port 
	 * could work.
	 */

	PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
	// Make sure the file object exists.
	if (FltObjects->FileObject != NULL) {
		// Get the file name information with the normalized name.
		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
		if (NT_SUCCESS(status)) {
			// Now we want to parse the file name information to get the extension.
			FltParseFileNameInformation(FileNameInfo);

			// Compare the file extension (case-insensitive) and check if it is protected.
			if (RtlCompareUnicodeString(&FileNameInfo->Extension, &ProtectedExtention, TRUE) == 0) {
				DBG_PRINT("Protecting file deletion/rename!");
				// Strings match, deny access!
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				// Complete the I/O request and send it back up.
				ret = FLT_PREOP_COMPLETE;
			}

			// Clean up file name information.
			FltReleaseFileNameInformation(FileNameInfo);
		}
	}

	return ret;
}
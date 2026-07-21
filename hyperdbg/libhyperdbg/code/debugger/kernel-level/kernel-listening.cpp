/**
 * @file kernel-listening.cpp
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @author Alee Amini (alee@hyperdbg.org)
 * @brief Listening for remote connections on kernel debugger
 * @details
 * @version 0.1
 * @date 2020-12-20
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

//
// Global Variables
//
extern BYTE                             g_CurrentRunningInstruction[MAXIMUM_INSTR_SIZE];
extern HANDLE                           g_SerialRemoteComPortHandle;
extern BOOLEAN                          g_IsSerialConnectedToRemoteDebuggee;
extern BOOLEAN                          g_IsDebuggeeRunning;
extern BOOLEAN                          g_IgnoreNewLoggingMessages;
extern BOOLEAN                          g_SharedEventStatus;
extern BOOLEAN                          g_IsRunningInstruction32Bit;
extern BOOLEAN                          g_OutputSourcesInitialized;
extern ULONG                            g_CurrentRemoteCore;
extern DEBUGGER_EVENT_AND_ACTION_RESULT g_DebuggeeResultOfRegisteringEvent;
extern DEBUGGER_EVENT_AND_ACTION_RESULT g_DebuggeeResultOfAddingActionsToEvent;
extern UINT64                           g_ResultOfEvaluatedExpression;
extern UINT32                           g_ErrorStateOfResultOfEvaluatedExpression;
extern UINT64                           g_KernelBaseAddress;
extern DEBUGGER_SYNCRONIZATION_EVENTS_STATE
    g_KernelSyncronizationObjectsHandleTable[DEBUGGER_MAXIMUM_SYNCRONIZATION_KERNEL_DEBUGGER_OBJECTS];

/**
 * @brief Check if the remote debuggee needs to pause the system
 * and also process the debuggee's messages
 *
 * @return BOOLEAN
 */
BOOLEAN
ListeningSerialPortInDebugger()
{
    PDEBUGGER_PREPARE_DEBUGGEE                   InitPacket;
    PDEBUGGER_REMOTE_PACKET                      TheActualPacket;
    PDEBUGGEE_KD_PAUSED_PACKET                   PausePacket;
    PDEBUGGEE_MESSAGE_PACKET                     MessagePacket;
    PDEBUGGEE_CHANGE_CORE_PACKET                 ChangeCorePacket;
    PDEBUGGEE_SCRIPT_PACKET                      ScriptPacket;
    PDEBUGGEE_FORMATS_PACKET                     FormatsPacket;
    PDEBUGGER_EVENT_AND_ACTION_RESULT            EventAndActionPacket;
    PDEBUGGER_UPDATE_SYMBOL_TABLE                SymbolUpdatePacket;
    PDEBUGGER_MODIFY_EVENTS                      EventModifyAndQueryPacket;
    PDEBUGGEE_SYMBOL_UPDATE_RESULT               SymbolReloadFinishedPacket;
    PDEBUGGEE_DETAILS_AND_SWITCH_PROCESS_PACKET  ChangeProcessPacket;
    PDEBUGGEE_RESULT_OF_SEARCH_PACKET            SearchResultsPacket;
    PDEBUGGEE_DETAILS_AND_SWITCH_THREAD_PACKET   ChangeThreadPacket;
    PDEBUGGER_FLUSH_LOGGING_BUFFERS              FlushPacket;
    PDEBUGGER_CPUID_REQUEST_RESPONSE             CpuidPacket;
    PDEBUGGER_CALLSTACK_REQUEST                  CallstackPacket;
    PDEBUGGER_SINGLE_CALLSTACK_FRAME             CallstackFramePacket;
    PDEBUGGER_DEBUGGER_TEST_QUERY_BUFFER         TestQueryPacket;
    PDEBUGGEE_REGISTER_READ_DESCRIPTION          ReadRegisterPacket;
    PDEBUGGEE_REGISTER_WRITE_DESCRIPTION         WriteRegisterPacket;
    PDEBUGGER_APIC_REQUEST                       ApicRequestPacket;
    PDEBUGGER_READ_MEMORY                        ReadMemoryPacket;
    PDEBUGGER_EDIT_MEMORY                        EditMemoryPacket;
    PDEBUGGEE_BP_PACKET                          BpPacket;
    PDEBUGGER_SHORT_CIRCUITING_EVENT             ShortCircuitingPacket;
    PDEBUGGER_READ_PAGE_TABLE_ENTRIES_DETAILS    PtePacket;
    PSMI_OPERATION_PACKETS                       SmiOperationPacket;
    PHYPERTRACE_LBR_DUMP_PACKETS                 HyperTraceLbrdumpPacket;
    PHYPERTRACE_PT_OPERATION_PACKETS             HyperTracePtOperationPacket;
    PDEBUGGER_PAGE_IN_REQUEST                    PageinPacket;
    PDEBUGGER_VA2PA_AND_PA2VA_COMMANDS           Va2paPa2vaPacket;
    PDEBUGGEE_BP_LIST_OR_MODIFY_PACKET           ListOrModifyBreakpointPacket;
    BOOLEAN                                      ShowSignatureWhenDisconnected = FALSE;
    PVOID                                        CallerAddress                 = NULL;
    UINT32                                       CallerSize                    = NULL_ZERO;
    PDEBUGGEE_PCITREE_REQUEST_RESPONSE_PACKET    PcitreePacket;
    PINTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS  IdtEntryRequestPacket;
    PDEBUGGEE_PCIDEVINFO_REQUEST_RESPONSE_PACKET PcidevinfoPacket;

StartAgain:

    CHAR   BufferToReceive[MaxSerialPacketSize] = {0};
    UINT32 LengthReceived                       = 0;

    //
    // Wait for handshake to complete or in other words
    // get the receive packet
    //
    if (!KdReceivePacketFromDebuggee(BufferToReceive, &LengthReceived))
    {
        if (LengthReceived == 0 && BufferToReceive[0] == NULL)
        {
            //
            // The remote computer (debuggee) closed the connection
            //
            ShowMessages("\nthe remote connection is closed\n");

            if (g_IsSerialConnectedToRemoteDebuggee)
            {
                //
                // Remove and reset all the events
                //
                CommandEventsClearAllEventsAndResetTags();

                if (g_IsDebuggeeRunning == FALSE)
                {
                    ShowSignatureWhenDisconnected = TRUE;
                }
            }

            KdCloseConnection();

            if (ShowSignatureWhenDisconnected)
            {
                ShowSignatureWhenDisconnected = FALSE;
                ShowMessages("\n");
            }
            return FALSE;
        }
        else
        {
            ShowMessages("err, invalid buffer received\n");
            goto StartAgain;
        }
    }

    //
    // Check for invalid close packets
    //
    if (LengthReceived == 1 && BufferToReceive[0] == NULL)
    {
        goto StartAgain;
    }

    TheActualPacket = (PDEBUGGER_REMOTE_PACKET)BufferToReceive;

    if (TheActualPacket->Indicator == INDICATOR_OF_HYPERDBG_PACKET)
    {
        //
        // Check checksum
        //
        if (KdComputeDataChecksum((PVOID)&TheActualPacket->Indicator,
                                  LengthReceived - sizeof(BYTE)) != TheActualPacket->Checksum)
        {
            ShowMessages("\nerr, checksum is invalid\n");
            goto StartAgain;
        }

        //
        // Check if the packet type is correct
        //
        if (TheActualPacket->TypeOfThePacket != DEBUGGER_REMOTE_PACKET_TYPE_DEBUGGEE_TO_DEBUGGER)
        {
            //
            // sth wrong happened, the packet is not belonging to use
            // nothing to do, just wait again
            //
            ShowMessages("\nerr, unknown packet received from the debuggee\n");
            goto StartAgain;
        }

        //
        // It's a HyperDbg packet
        //
        switch (TheActualPacket->RequestedActionOfThePacket)
        {
        case DEBUGGER_REMOTE_PACKET_PING_AND_SEND_SUPPORTED_VERSION:

            //
            // Send the handshake response
            //
            KdSendResponseOfThePingPacket();

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_STARTED:

            InitPacket = (DEBUGGER_PREPARE_DEBUGGEE *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Set the kernel base address
            //
            g_KernelBaseAddress = InitPacket->KernelBaseAddress;

            ShowMessages("connected to debuggee %s\n", InitPacket->OsName);

            //
            // Signal the event that the debugger started
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_STARTED_PACKET_RECEIVED);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_LOGGING_MECHANISM:

            MessagePacket = (DEBUGGEE_MESSAGE_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Check if there are available output sources
            //
            if (!g_OutputSourcesInitialized || !ForwardingCheckAndPerformEventForwarding(MessagePacket->OperationCode,
                                                                                         MessagePacket->Message,
                                                                                         (UINT32)strlen(MessagePacket->Message)))
            {
                //
                // We check g_IgnoreNewLoggingMessages here because we want to
                // avoid messages when the debuggee is halted
                //
                if (!g_IgnoreNewLoggingMessages)
                {
                    ShowMessages("%s", MessagePacket->Message);
                }
            }

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_PAUSED_AND_CURRENT_INSTRUCTION:

            //
            // Pause logging mechanism
            //
            g_IgnoreNewLoggingMessages = TRUE;

            PausePacket = (DEBUGGEE_KD_PAUSED_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Debuggee is not running
            //
            g_IsDebuggeeRunning = FALSE;

            //
            // Set the current core
            //
            g_CurrentRemoteCore = PausePacket->CurrentCore;

            //
            // Save the current operating instruction and operating mode
            //
            PlatformZeroMemory(g_CurrentRunningInstruction, MAXIMUM_INSTR_SIZE);
            memcpy(g_CurrentRunningInstruction, &PausePacket->InstructionBytesOnRip, MAXIMUM_INSTR_SIZE);

            g_IsRunningInstruction32Bit = PausePacket->IsProcessorOn32BitMode;

            //
            // Show additional messages before showing assembly and pausing
            //
            switch (PausePacket->PausingReason)
            {
            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_SOFTWARE_BREAKPOINT_HIT:

                if (PausePacket->EventTag != NULL)
                {
                    //
                    // It's a breakpoint id
                    //
                    ShowMessages("breakpoint 0x%x hit\n",
                                 PausePacket->EventTag);
                }

                break;

            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_EVENT_TRIGGERED:

                if (PausePacket->EventTag != NULL)
                {
                    //
                    // It's an event tag
                    //
                    if (PausePacket->EventCallingStage == VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION)
                    {
                        ShowMessages("event 0x%x triggered (post)\n",
                                     PausePacket->EventTag - DebuggerEventTagStartSeed);
                    }
                    else
                    {
                        ShowMessages("event 0x%x triggered (pre)\n",
                                     PausePacket->EventTag - DebuggerEventTagStartSeed);
                    }
                }

                break;

            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_PROCESS_SWITCHED:

                ShowMessages("switched to the specified process\n");

                break;

            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_THREAD_SWITCHED:

                ShowMessages("switched to the specified thread\n");

                break;

            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_STARTING_MODULE_LOADED:

                ShowMessages("the target module is loaded and a breakpoint is set to the entrypoint\n"
                             "press 'g' to reach to the entrypoint of the main module...\n");

                break;

            default:
                break;
            }

            if (!PausePacket->IgnoreDisassembling)
            {
                //
                // Check if the instruction is received completely or not
                //
                if (PausePacket->ReadInstructionLen != MAXIMUM_INSTR_SIZE)
                {
                    //
                    // We check if the disassembled buffer has greater size
                    // than what is retrieved
                    //
                    if (HyperDbgLengthDisassemblerEngine(PausePacket->InstructionBytesOnRip,
                                                         MAXIMUM_INSTR_SIZE,
                                                         PausePacket->IsProcessorOn32BitMode ? FALSE : TRUE) > PausePacket->ReadInstructionLen)
                    {
                        ShowMessages("oOh, no! there might be a misinterpretation in disassembling the current instruction\n");
                    }
                }

                if (!PausePacket->IsProcessorOn32BitMode)
                {
                    //
                    // Show diassembles
                    //
                    HyperDbgDisassembler64(PausePacket->InstructionBytesOnRip,
                                           PausePacket->Rip,
                                           MAXIMUM_INSTR_SIZE,
                                           1,
                                           TRUE,
                                           (PRFLAGS)&PausePacket->Rflags);
                }
                else
                {
                    //
                    // Show diassembles
                    //
                    HyperDbgDisassembler32(PausePacket->InstructionBytesOnRip,
                                           PausePacket->Rip,
                                           MAXIMUM_INSTR_SIZE,
                                           1,
                                           TRUE,
                                           (PRFLAGS)&PausePacket->Rflags);
                }
            }

            switch (PausePacket->PausingReason)
            {
            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_SOFTWARE_BREAKPOINT_HIT:
            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_HARDWARE_DEBUG_REGISTER_HIT:
            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_EVENT_TRIGGERED:
            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_STEPPED:
            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_PROCESS_SWITCHED:
            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_THREAD_SWITCHED:

                //
                // Unpause the debugger to get commands
                //
                DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_IS_DEBUGGER_RUNNING);

                break;

            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_TRACKING_STEPPED:

                //
                // Handle the tracking of the 'ret' and the 'call' instructions
                //
                CommandTrackHandleReceivedInstructions(&PausePacket->InstructionBytesOnRip[0],
                                                       MAXIMUM_INSTR_SIZE,
                                                       PausePacket->IsProcessorOn32BitMode ? FALSE : TRUE,
                                                       PausePacket->Rip);

                //
                // Unpause the debugger to get commands
                //
                DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_IS_DEBUGGER_RUNNING);

                break;

            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_STARTING_MODULE_LOADED:

                //
                // Unpause the debugger to get commands
                //
                ShowMessages("\n");
                DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_IS_DEBUGGER_RUNNING);

                break;

            case DEBUGGEE_PAUSING_REASON_PAUSE:

                //
                // Nothing
                //
                break;

            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_CORE_SWITCHED:

                //
                // Signal the event relating to receiving result of core change
                //
                DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_CORE_SWITCHING_RESULT);

                break;

            case DEBUGGEE_PAUSING_REASON_DEBUGGEE_COMMAND_EXECUTION_FINISHED:

                //
                // Signal the event relating to result of command execution finished
                //
                ShowMessages("\n");
                DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_DEBUGGEE_FINISHED_COMMAND_EXECUTION);

                break;

            case DEBUGGEE_PAUSING_REASON_REQUEST_FROM_DEBUGGER:

                //
                // Signal the event relating to commands that are waiting for
                // the details of a halted debuggeee
                //
                DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_PAUSED_DEBUGGEE_DETAILS);

                break;

            default:

                ShowMessages("err, unknown pausing reason is received\n");

                break;
            }

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_CHANGING_CORE:

            ChangeCorePacket = (DEBUGGEE_CHANGE_CORE_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (ChangeCorePacket->Result == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                ShowMessages("current operating core changed to 0x%x\n",
                             ChangeCorePacket->NewCore);
            }
            else
            {
                ShowErrorMessage(ChangeCorePacket->Result);

                //
                // Signal the event relating to receiving result of core change
                //
                DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_CORE_SWITCHING_RESULT);
            }

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_CHANGING_PROCESS:

            ChangeProcessPacket = (DEBUGGEE_DETAILS_AND_SWITCH_PROCESS_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (ChangeProcessPacket->Result == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                if (ChangeProcessPacket->ActionType == DEBUGGEE_DETAILS_AND_SWITCH_PROCESS_GET_PROCESS_DETAILS)
                {
                    ShowMessages("process id: %x\nprocess (_EPROCESS): %s\nprocess name (16-Byte): %s\n",
                                 ChangeProcessPacket->ProcessId,
                                 SeparateTo64BitValue(ChangeProcessPacket->Process).c_str(),
                                 &ChangeProcessPacket->ProcessName);
                }
                else if (ChangeProcessPacket->ActionType == DEBUGGEE_DETAILS_AND_SWITCH_PROCESS_PERFORM_SWITCH)
                {
                    ShowMessages(
                        "press 'g' to continue the debuggee, if the pid or the "
                        "process object address is valid then the debuggee will "
                        "be automatically paused when it attached to the target process\n");
                }
            }
            else
            {
                ShowErrorMessage(ChangeProcessPacket->Result);
            }

            //
            // Signal the event relating to receiving result of process change
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_PROCESS_SWITCHING_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RELOAD_SEARCH_QUERY:

            SearchResultsPacket = (DEBUGGEE_RESULT_OF_SEARCH_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (SearchResultsPacket->Result == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                if (SearchResultsPacket->CountOfResults == 0)
                {
                    ShowMessages("not found\n");
                }
            }
            else
            {
                ShowErrorMessage(SearchResultsPacket->Result);
            }

            //
            // Signal the event relating to receiving result of search query
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_SEARCH_QUERY_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_CHANGING_THREAD:

            ChangeThreadPacket = (DEBUGGEE_DETAILS_AND_SWITCH_THREAD_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (ChangeThreadPacket->Result == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                if (ChangeThreadPacket->ActionType == DEBUGGEE_DETAILS_AND_SWITCH_THREAD_GET_THREAD_DETAILS)
                {
                    ShowMessages("thread id: %x (pid: %x)\nthread (_ETHREAD): %s\nprocess (_EPROCESS): %s\nprocess name (16-Byte): %s\n",
                                 ChangeThreadPacket->ThreadId,
                                 ChangeThreadPacket->ProcessId,
                                 SeparateTo64BitValue(ChangeThreadPacket->Thread).c_str(),
                                 SeparateTo64BitValue(ChangeThreadPacket->Process).c_str(),
                                 &ChangeThreadPacket->ProcessName);
                }
                else if (ChangeThreadPacket->ActionType == DEBUGGEE_DETAILS_AND_SWITCH_THREAD_PERFORM_SWITCH)
                {
                    ShowMessages(
                        "press 'g' to continue the debuggee, if the tid or the "
                        "thread object address is valid then the debuggee will "
                        "be automatically paused when it attached to the target thread\n");
                }
            }
            else
            {
                ShowErrorMessage(ChangeThreadPacket->Result);
            }

            //
            // Signal the event relating to receiving result of thread change
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_THREAD_SWITCHING_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_FLUSH:

            FlushPacket = (DEBUGGER_FLUSH_LOGGING_BUFFERS *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (FlushPacket->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                //
                // The amount of message that are deleted are the amount of
                // vmx-root messages and vmx non-root messages
                //
                ShowMessages("flushing buffers was successful, total %d messages were "
                             "cleared.\n",
                             FlushPacket->CountOfMessagesThatSetAsReadFromVmxNonRoot + FlushPacket->CountOfMessagesThatSetAsReadFromVmxRoot);
            }
            else
            {
                ShowErrorMessage(FlushPacket->KernelStatus);
            }

            //
            // Signal the event relating to receiving result of flushing
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_FLUSH_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_USER_CPUID:

            CpuidPacket = (DEBUGGER_CPUID_REQUEST_RESPONSE *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (CpuidPacket->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                UINT32                          FunctionId    = CpuidPacket->FunctionId;
                UINT32                          SubFunctionId = CpuidPacket->SubFunctionId;
                CONST CHAR *                    TypeName      = NULL;
                CONST CHAR *                    AssocName;
                                
                switch (FunctionId)
                {
                case 0x0:
                {
                    CHAR Vendor[13] = {0};
                    memcpy(&Vendor[0], &CpuidPacket->EBX, 4);
                    memcpy(&Vendor[4], &CpuidPacket->EDX, 4);
                    memcpy(&Vendor[8], &CpuidPacket->ECX, 4);
                    Vendor[12] = '\0';

                    ShowMessages("  *******************************************************\n"
                                 "  *               LEAF 0 HAS NO SUBLEAVES               *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    ShowMessages("  Vendor : %s\n", Vendor);
                    ShowMessages("  Maximum supported basic leaf : %u\n", CpuidPacket->EAX);

                    break;
                }
                case 0x1:
                    //
                    // EAX
                    //
                    ShowMessages("==== CPUID.(EAX=01H) Version / Additional / Feature Information ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *               LEAF 1 HAS NO SUBLEAVES               *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    ShowMessages("-- EAX: Version Information --\n\n");
                    ShowMessages("  SteppingId       = %u\n",
                                 CPUID_VERSION_INFORMATION_STEPPING_ID(CpuidPacket->EAX));
                    ShowMessages("  Model            = %u\n",
                                 CPUID_VERSION_INFORMATION_MODEL(CpuidPacket->EAX));
                    ShowMessages("  FamilyId         = %u\n",
                                 CPUID_VERSION_INFORMATION_FAMILY_ID(CpuidPacket->EAX));
                    ShowMessages("  ProcessorType    = %u\n",
                                 CPUID_VERSION_INFORMATION_PROCESSOR_TYPE(CpuidPacket->EAX));
                    ShowMessages("  ExtendedModelId  = %u\n",
                                 CPUID_VERSION_INFORMATION_EXTENDED_MODEL_ID(CpuidPacket->EAX));
                    ShowMessages("  ExtendedFamilyId = %u\n\n",
                                 CPUID_VERSION_INFORMATION_EXTENDED_FAMILY_ID(CpuidPacket->EAX));

                    //
                    // EBX: additional information
                    //
                    ShowMessages("-- EBX: Additional Information --\n\n");
                    ShowMessages("  BrandIndex        = %u\n",
                                 CPUID_ADDITIONAL_INFORMATION_BRAND_INDEX(CpuidPacket->EBX));
                    ShowMessages("  ClflushLineSize   = %u (cache line = %u bytes)\n",
                                 CPUID_ADDITIONAL_INFORMATION_CLFLUSH_LINE_SIZE(CpuidPacket->EBX),
                                 CPUID_ADDITIONAL_INFORMATION_CLFLUSH_LINE_SIZE(CpuidPacket->EBX) * 8);
                    ShowMessages("  MaxAddressableIds = %u\n",
                                 CPUID_ADDITIONAL_INFORMATION_MAX_ADDRESSABLE_IDS(CpuidPacket->EBX));
                    ShowMessages("  InitialApicId     = %u\n\n",
                                 CPUID_ADDITIONAL_INFORMATION_INITIAL_APIC_ID(CpuidPacket->EBX));

                    //
                    // ECX: feature information
                    //
                    ShowMessages("-- ECX: Feature Information --\n\n");
                    ShowMessages("  SSE3                  = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_STREAMING_SIMD_EXTENSIONS_3(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  PCLMULQDQ             = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_PCLMULQDQ_INSTRUCTION(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  DTES64                = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_DS_AREA_64BIT_LAYOUT(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  MONITOR/MWAIT         = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_MONITOR_MWAIT_INSTRUCTION(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  CPL Qualified DS      = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_CPL_QUALIFIED_DEBUG_STORE(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  VMX                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_VIRTUAL_MACHINE_EXTENSIONS(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  SMX                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_SAFER_MODE_EXTENSIONS(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  EIST (SpeedStep)      = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_ENHANCED_INTEL_SPEEDSTEP_TECHNOLOGY(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  TM2                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_THERMAL_MONITOR_2(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  SSSE3                 = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_SUPPLEMENTAL_STREAMING_SIMD_EXTENSIONS_3(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  L1 Context ID         = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_L1_CONTEXT_ID(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  Silicon Debug         = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_SILICON_DEBUG(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  FMA                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_FMA_EXTENSIONS(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  CMPXCHG16B            = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_CMPXCHG16B_INSTRUCTION(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  xTPR Update Control   = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_XTPR_UPDATE_CONTROL(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  PDCM                  = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_PERFMON_AND_DEBUG_CAPABILITY(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  PCID                  = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_PROCESS_CONTEXT_IDENTIFIERS(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  DCA                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_DIRECT_CACHE_ACCESS(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  SSE4.1                = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_SSE41_SUPPORT(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  SSE4.2                = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_SSE42_SUPPORT(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  x2APIC                = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_X2APIC_SUPPORT(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  MOVBE                 = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_MOVBE_INSTRUCTION(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  POPCNT                = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_POPCNT_INSTRUCTION(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  TSC-Deadline          = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_TSC_DEADLINE(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  AESNI                 = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_AESNI_INSTRUCTION_EXTENSIONS(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  XSAVE/XRSTOR          = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_XSAVE_XRSTOR_INSTRUCTION(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  OSXSAVE               = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_OSX_SAVE(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  AVX                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_AVX_SUPPORT(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  F16C                  = %s\n",
                                 CPUID_FEATURE_INFORMATION_ECX_HALF_PRECISION_CONVERSION_INSTRUCTIONS(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  RDRAND                = %s\n\n",
                                 CPUID_FEATURE_INFORMATION_ECX_RDRAND_INSTRUCTION(CpuidPacket->ECX) ? "TRUE" : "FALSE");

                    //
                    // EDX: feature information
                    //
                    ShowMessages("-- EDX: Feature Information --\n\n");
                    ShowMessages("  FPU                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_FLOATING_POINT_UNIT_ON_CHIP(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  VME                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_VIRTUAL_8086_MODE_ENHANCEMENTS(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  DE                    = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_DEBUGGING_EXTENSIONS(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  PSE                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_PAGE_SIZE_EXTENSION(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  TSC                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_TIMESTAMP_COUNTER(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  MSR (RDMSR/WRMSR)     = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_RDMSR_WRMSR_INSTRUCTIONS(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  PAE                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_PHYSICAL_ADDRESS_EXTENSION(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  MCE                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_MACHINE_CHECK_EXCEPTION(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  CX8 (CMPXCHG8B)       = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_CMPXCHG8B(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  APIC On-Chip          = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_APIC_ON_CHIP(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  SEP (SYSENTER/EXIT)   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_SYSENTER_SYSEXIT_INSTRUCTIONS(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  MTRR                  = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_MEMORY_TYPE_RANGE_REGISTERS(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  PGE                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_PAGE_GLOBAL_BIT(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  MCA                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_MACHINE_CHECK_ARCHITECTURE(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  CMOV                  = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_CONDITIONAL_MOVE_INSTRUCTIONS(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  PAT                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_PAGE_ATTRIBUTE_TABLE(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  PSE-36                = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_PAGE_SIZE_EXTENSION_36BIT(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  PSN                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_PROCESSOR_SERIAL_NUMBER(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  CLFSH                 = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_CLFLUSH(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  DS (Debug Store)      = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_DEBUG_STORE(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  ACPI (Thermal/Clock)  = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_THERMAL_CONTROL_MSRS_FOR_ACPI(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  MMX                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_MMX_SUPPORT(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  FXSR (FXSAVE/FXRSTOR) = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_FXSAVE_FXRSTOR_INSTRUCTIONS(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  SSE                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_SSE_SUPPORT(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  SSE2                  = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_SSE2_SUPPORT(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  SS (Self Snoop)       = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_SELF_SNOOP(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  HTT                   = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_HYPER_THREADING_TECHNOLOGY(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  TM (Thermal Monitor)  = %s\n",
                                 CPUID_FEATURE_INFORMATION_EDX_THERMAL_MONITOR(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  PBE                   = %s\n\n",
                                 CPUID_FEATURE_INFORMATION_EDX_PENDING_BREAK_ENABLE(CpuidPacket->EDX) ? "TRUE" : "FALSE");

                    break;

                case 0x2:
                    ShowMessages("==== CPUID.(EAX=02H) Legacy Cache Descriptor ====\n\n");
                    ShowMessages("  This leaf is deprecated and returns legacy cache information.\n");
                    ShowMessages("  Use CPUID.(EAX=04H) for deterministic cache parameters instead.\n\n");
                    ShowMessages("  Raw data:\n");
                    ShowMessages("  EAX: 0x%08X\n", CpuidPacket->EAX);
                    ShowMessages("  EBX: 0x%08X\n", CpuidPacket->EBX);
                    ShowMessages("  ECX: 0x%08X\n", CpuidPacket->ECX);
                    ShowMessages("  EDX: 0x%08X\n\n", CpuidPacket->EDX);
                    break;

                case 0x3:
                    ShowMessages("==== CPUID.(EAX=03H) ====\n\n");
                    ShowMessages("  This leaf is reserved/not implemented on modern processors.\n");
                    ShowMessages("  (Was previously used for Processor Serial Number on older CPUs)\n\n");
                    ShowMessages("  Raw data:\n");
                    ShowMessages("  EAX: 0x%08X\n", CpuidPacket->EAX);
                    ShowMessages("  EBX: 0x%08X\n", CpuidPacket->EBX);
                    ShowMessages("  ECX: 0x%08X\n", CpuidPacket->ECX);
                    ShowMessages("  EDX: 0x%08X\n\n", CpuidPacket->EDX);
                    break;

                case 0x4:
                {
                    UINT32 LineSize       = CPUID_EBX_SYSTEM_COHERENCY_LINE_SIZE(CpuidPacket->EBX);
                    UINT32 Partitions     = CPUID_EBX_PHYSICAL_LINE_PARTITIONS(CpuidPacket->EBX);
                    UINT32 Ways           = CPUID_EBX_WAYS_OF_ASSOCIATIVITY(CpuidPacket->EBX);
                    UINT32 Sets           = CPUID_ECX_NUMBER_OF_SETS(CpuidPacket->ECX);
                    UINT64 CacheSizeBytes = (UINT64)(Ways + 1) *
                                            (UINT64)(Partitions + 1) *
                                            (UINT64)(LineSize + 1) *
                                            (UINT64)(Sets + 1);
                    ShowMessages("==== CPUID.(EAX=04H) Deterministic Cache Parameters ====\n\n");

                    ShowMessages("  *******************************************************\n"
                                 "  *             Max NumberOfSubLeaves = %u               *\n"
                                 "  *******************************************************\n\n",
                                 CpuidPacket->Leaf4MaxSubLeaf);

                    ShowMessages("---- CPUID.(EAX=04H, ECX=%u) ----\n\n", SubFunctionId);

                    //
                    // EAX
                    //
                    switch (CPUID_EAX_CACHE_TYPE_FIELD(CpuidPacket->EAX))
                    {
                    case 0:
                        TypeName = "Null (no more caches)";
                        break;
                    case 1:
                        TypeName = "Data Cache";
                        break;
                    case 2:
                        TypeName = "Instruction Cache";
                        break;
                    case 3:
                        TypeName = "Unified Cache";
                        break;
                    default:
                        TypeName = "Reserved";
                        break;
                    }

                    ShowMessages("-- EAX --\n\n");
                    ShowMessages("  CacheTypeField                   = %u (%s)\n",
                                 CPUID_EAX_CACHE_TYPE_FIELD(CpuidPacket->EAX),
                                 TypeName);

                    if (CPUID_EAX_CACHE_TYPE_FIELD(CpuidPacket->EAX) == 0)
                    {
                        ShowMessages("  (no more caches; stopping enumeration)\n\n");
                        break;
                    }

                    ShowMessages("  CacheLevel                       = %u\n",
                                 CPUID_EAX_CACHE_LEVEL(CpuidPacket->EAX));
                    ShowMessages("  SelfInitializingCacheLevel       = %s\n",
                                 CPUID_EAX_SELF_INITIALIZING_CACHE_LEVEL(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  FullyAssociativeCache            = %s%s\n",
                                 CPUID_EAX_FULLY_ASSOCIATIVE_CACHE(CpuidPacket->EAX) ? "TRUE" : "FALSE",
                                 CPUID_EAX_FULLY_ASSOCIATIVE_CACHE(CpuidPacket->EAX) ? " (fully associative)" : "");

                    ShowMessages("  MaxAddressableIds(LogicalProcs)  (raw) = %u -> actual = %u (raw + 1)\n",
                                 CPUID_EAX_MAX_ADDRESSABLE_IDS_FOR_LOGICAL_PROCESSORS_SHARING_THIS_CACHE(CpuidPacket->EAX),
                                 CPUID_EAX_MAX_ADDRESSABLE_IDS_FOR_LOGICAL_PROCESSORS_SHARING_THIS_CACHE(CpuidPacket->EAX) + 1);
                    ShowMessages("  MaxAddressableIds(Cores)         (raw) = %u -> actual = %u (raw + 1)\n\n",
                                 CPUID_EAX_MAX_ADDRESSABLE_IDS_FOR_PROCESSOR_CORES_IN_PHYSICAL_PACKAGE(CpuidPacket->EAX),
                                 CPUID_EAX_MAX_ADDRESSABLE_IDS_FOR_PROCESSOR_CORES_IN_PHYSICAL_PACKAGE(CpuidPacket->EAX) + 1);

                    //
                    // EBX
                    //
                    ShowMessages("-- EBX --\n\n");

                    ShowMessages("  SystemCoherencyLineSize          (raw) = %u -> actual = %u bytes (raw + 1)\n",
                                 LineSize,
                                 LineSize + 1);
                    ShowMessages("  PhysicalLinePartitions           (raw) = %u -> actual = %u (raw + 1)\n",
                                 Partitions,
                                 Partitions + 1);
                    ShowMessages("  WaysOfAssociativity              (raw) = %u -> actual = %u (raw + 1)\n\n",
                                 Ways,
                                 Ways + 1);

                    //
                    // ECX
                    //
                    ShowMessages("-- ECX --\n\n");

                    ShowMessages("  NumberOfSets                     (raw) = %u -> actual = %u (raw + 1)\n\n",
                                 Sets,
                                 Sets + 1);

                    //
                    // EDX
                    //
                    ShowMessages("-- EDX --\n\n");
                    ShowMessages("  WriteBackInvalidate              = %s\n",
                                 CPUID_EDX_WRITE_BACK_INVALIDATE(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    ShowMessages("  CacheInclusiveness               = %s%s\n",
                                 CPUID_EDX_CACHE_INCLUSIVENESS(CpuidPacket->EDX) ? "TRUE" : "FALSE",
                                 CPUID_EDX_CACHE_INCLUSIVENESS(CpuidPacket->EDX) ? " (inclusive of lower levels)" : "");
                    ShowMessages("  ComplexCacheIndexing             = %s%s\n\n",
                                 CPUID_EDX_COMPLEX_CACHE_INDEXING(CpuidPacket->EDX) ? "TRUE" : "FALSE",
                                 CPUID_EDX_COMPLEX_CACHE_INDEXING(CpuidPacket->EDX) ? " (complex/hashed indexing)" : " (direct mapped)");

                    //
                    // Cache Size Calculation (from spec formula)
                    //
                    ShowMessages("-- Cache Size --\n\n");
                    ShowMessages("  Cache Size (per spec formula)    = %llu bytes (%llu KB, %llu MB)\n\n",
                                 (ULONG64)CacheSizeBytes,
                                 (ULONG64)(CacheSizeBytes / 1024),
                                 (ULONG64)(CacheSizeBytes / (1024 * 1024)));

                    break;
                }
                case 0x5:
                    ShowMessages("==== CPUID.(EAX=05H) MONITOR/MWAIT Leaf ====\n\n");

                    ShowMessages("  *******************************************************\n"
                                 "  *               LEAF 5 HAS NO SUBLEAVES               *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    //
                    // EAX
                    //
                    ShowMessages("-- EAX --\n\n");
                    ShowMessages("  SmallestMonitorLineSize = %u bytes\n\n",
                                 CPUID_EAX_SMALLEST_MONITOR_LINE_SIZE(CpuidPacket->EAX));

                    //
                    // EBX
                    //
                    ShowMessages("-- EBX --\n\n");
                    ShowMessages("  LargestMonitorLineSize  = %u bytes\n\n",
                                 CPUID_EBX_LARGEST_MONITOR_LINE_SIZE(CpuidPacket->EBX));

                    //
                    // ECX
                    //
                    ShowMessages("-- ECX --\n\n");
                    ShowMessages("  EnumerationOfMonitorMwaitExtensions             = %s\n",
                                 CPUID_ECX_ENUMERATION_OF_MONITOR_MWAIT_EXTENSIONS(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  SupportsTreatingInterruptsAsBreakEventForMwait  = %s\n\n",
                                 CPUID_ECX_SUPPORTS_TREATING_INTERRUPTS_AS_BREAK_EVENT_FOR_MWAIT(CpuidPacket->ECX) ? "TRUE" : "FALSE");

                    //
                    // EDX
                    //
                    ShowMessages("-- EDX --\n\n");
                    ShowMessages("  NumberOfC0SubCStates = %u\n", CPUID_EDX_NUMBER_OF_C0_SUB_C_STATES(CpuidPacket->EDX));
                    ShowMessages("  NumberOfC1SubCStates = %u\n", CPUID_EDX_NUMBER_OF_C1_SUB_C_STATES(CpuidPacket->EDX));
                    ShowMessages("  NumberOfC2SubCStates = %u\n", CPUID_EDX_NUMBER_OF_C2_SUB_C_STATES(CpuidPacket->EDX));
                    ShowMessages("  NumberOfC3SubCStates = %u\n", CPUID_EDX_NUMBER_OF_C3_SUB_C_STATES(CpuidPacket->EDX));
                    ShowMessages("  NumberOfC4SubCStates = %u\n", CPUID_EDX_NUMBER_OF_C4_SUB_C_STATES(CpuidPacket->EDX));
                    ShowMessages("  NumberOfC5SubCStates = %u\n", CPUID_EDX_NUMBER_OF_C5_SUB_C_STATES(CpuidPacket->EDX));
                    ShowMessages("  NumberOfC6SubCStates = %u\n", CPUID_EDX_NUMBER_OF_C6_SUB_C_STATES(CpuidPacket->EDX));
                    ShowMessages("  NumberOfC7SubCStates = %u\n\n", CPUID_EDX_NUMBER_OF_C7_SUB_C_STATES(CpuidPacket->EDX));

                    break;

                case 0x6:
                    ShowMessages("==== CPUID.(EAX=06H) Thermal and Power Management Leaf ====\n\n");

                    ShowMessages("  *******************************************************\n"
                                 "  *               LEAF 6 HAS NO SUBLEAVES               *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    //
                    // EAX
                    //
                    ShowMessages("-- EAX --\n\n");
                    ShowMessages("  TemperatureSensorSupported              = %s\n",
                                 CPUID_EAX_TEMPERATURE_SENSOR_SUPPORTED(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  IntelTurboBoostTechnologyAvailable       = %s\n",
                                 CPUID_EAX_INTEL_TURBO_BOOST_TECHNOLOGY_AVAILABLE(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  ARAT (ApicTimerAlwaysRunning)            = %s\n",
                                 CPUID_EAX_APIC_TIMER_ALWAYS_RUNNING(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  PLN (PowerLimitNotification)             = %s\n",
                                 CPUID_EAX_POWER_LIMIT_NOTIFICATION(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  ECMD (ClockModulationDuty)               = %s\n",
                                 CPUID_EAX_CLOCK_MODULATION_DUTY(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  PTM (PackageThermalManagement)           = %s\n",
                                 CPUID_EAX_PACKAGE_THERMAL_MANAGEMENT(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  HWP Base Registers                       = %s\n",
                                 CPUID_EAX_HWP_BASE_REGISTERS(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  HWP_Notification                         = %s\n",
                                 CPUID_EAX_HWP_NOTIFICATION(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  HWP_Activity_Window                      = %s\n",
                                 CPUID_EAX_HWP_ACTIVITY_WINDOW(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  HWP_Energy_Performance_Preference        = %s\n",
                                 CPUID_EAX_HWP_ENERGY_PERFORMANCE_PREFERENCE(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  HWP_Package_Level_Request                = %s\n",
                                 CPUID_EAX_HWP_PACKAGE_LEVEL_REQUEST(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  HDC                                      = %s\n",
                                 CPUID_EAX_HDC(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  Intel Turbo Boost Max Technology 3.0     = %s\n",
                                 CPUID_EAX_INTEL_TURBO_BOOST_MAX_TECHNOLOGY_3_AVAILABLE(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  HWP Capabilities                         = %s\n",
                                 CPUID_EAX_HWP_CAPABILITIES(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  HWP PECI Override                        = %s\n",
                                 CPUID_EAX_HWP_PECI_OVERRIDE(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  Flexible HWP                             = %s\n",
                                 CPUID_EAX_FLEXIBLE_HWP(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  Fast Access Mode for HWP Request MSR     = %s\n",
                                 CPUID_EAX_FAST_ACCESS_MODE_FOR_HWP_REQUEST_MSR(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  Ignoring Idle Logical Proc HWP Request   = %s\n",
                                 CPUID_EAX_IGNORING_IDLE_LOGICAL_PROCESSOR_HWP_REQUEST(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                    ShowMessages("  Intel Thread Director                    = %s\n\n",
                                 CPUID_EAX_INTEL_THREAD_DIRECTOR(CpuidPacket->EAX) ? "TRUE" : "FALSE");

                    //
                    // EBX
                    //
                    ShowMessages("-- EBX --\n\n");
                    ShowMessages("  NumberOfInterruptThresholdsInThermalSensor = %u\n\n",
                                 CPUID_EBX_NUMBER_OF_INTERRUPT_THRESHOLDS_IN_THERMAL_SENSOR(CpuidPacket->EBX));

                    //
                    // ECX
                    //
                    ShowMessages("-- ECX --\n\n");
                    ShowMessages("  HardwareCoordinationFeedbackCapability   = %s\n",
                                 CPUID_ECX_HARDWARE_COORDINATION_FEEDBACK_CAPABILITY(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  NumberOfIntelThreadDirectorClasses (bit) = %s\n",
                                 CPUID_ECX_NUMBER_OF_INTEL_THREAD_DIRECTOR_CLASSES(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                    ShowMessages("  PerformanceEnergyBiasPreference          = %u\n\n",
                                 CPUID_ECX_PERFORMANCE_ENERGY_BIAS_PREFERENCE(CpuidPacket->ECX));

                    //
                    // EDX
                    // EDX is fully reserved for this leaf; still routed through its macro for consistency.
                    //
                    ShowMessages("-- EDX --\n\n");
                    ShowMessages("  Reserved                                 = 0x%08X\n\n", CPUID_EDX_RESERVED(CpuidPacket->EDX));

                    break;

                case 0x7:
                    ShowMessages("==== CPUID.(EAX=07H) Structured Extended Feature Flags ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *             Max NumberOfSubLeaves = %u               *\n"
                                 "  *******************************************************\n\n",
                                 CpuidPacket->LeafEaxMaxSubleaf);

                    if (SubFunctionId == 0)
                    {
                        ShowMessages("---- CPUID.(EAX=07H, ECX=%u) ----\n\n", SubFunctionId);

                        //
                        // EAX
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  NumberOfSubLeaves (max ECX input) = %u\n\n", CPUID_EAX_NUMBER_OF_SUB_LEAVES(CpuidPacket->EAX));

                        //
                        // EBX
                        //
                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  FSGSBASE                       = %s\n", CPUID_EBX_FSGSBASE(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  IA32_TSC_ADJUST MSR            = %s\n", CPUID_EBX_IA32_TSC_ADJUST_MSR(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  SGX                            = %s\n", CPUID_EBX_SGX(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  BMI1                           = %s\n", CPUID_EBX_BMI1(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  HLE                            = %s\n", CPUID_EBX_HLE(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX2                           = %s\n", CPUID_EBX_AVX2(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  FDP_EXCPTN_ONLY                = %s\n", CPUID_EBX_FDP_EXCPTN_ONLY(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  SMEP                           = %s\n", CPUID_EBX_SMEP(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  BMI2                           = %s\n", CPUID_EBX_BMI2(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  Enhanced REP MOVSB/STOSB       = %s\n", CPUID_EBX_ENHANCED_REP_MOVSB_STOSB(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  INVPCID                        = %s\n", CPUID_EBX_INVPCID(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  RTM                            = %s\n", CPUID_EBX_RTM(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  RDT-M (Monitoring)             = %s\n", CPUID_EBX_RDT_M(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  Deprecates FPU CS/DS           = %s\n", CPUID_EBX_DEPRECATES(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  MPX                            = %s\n", CPUID_EBX_MPX(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  RDT-A (Allocation)             = %s\n", CPUID_EBX_RDT(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512F                        = %s\n", CPUID_EBX_AVX512F(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512DQ                       = %s\n", CPUID_EBX_AVX512DQ(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  RDSEED                         = %s\n", CPUID_EBX_RDSEED(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  ADX                            = %s\n", CPUID_EBX_ADX(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  SMAP                           = %s\n", CPUID_EBX_SMAP(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512_IFMA                    = %s\n", CPUID_EBX_AVX512_IFMA(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  CLFLUSHOPT                     = %s\n", CPUID_EBX_CLFLUSHOPT(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  CLWB                           = %s\n", CPUID_EBX_CLWB(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  Intel Processor Trace          = %s\n", CPUID_EBX_INTEL(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512PF (Xeon Phi only)       = %s\n", CPUID_EBX_AVX512PF(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512ER (Xeon Phi only)       = %s\n", CPUID_EBX_AVX512ER(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512CD                       = %s\n", CPUID_EBX_AVX512CD(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  SHA                            = %s\n", CPUID_EBX_SHA(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512BW                       = %s\n", CPUID_EBX_AVX512BW(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512VL                       = %s\n\n", CPUID_EBX_AVX512VL(CpuidPacket->EBX) ? "TRUE" : "FALSE");

                        //
                        // ECX
                        //
                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  PREFETCHWT1 (Xeon Phi only)    = %s\n", CPUID_ECX_PREFETCHWT1(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512_VBMI                    = %s\n", CPUID_ECX_AVX512_VBMI(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  UMIP                           = %s\n", CPUID_ECX_UMIP(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  PKU                            = %s\n", CPUID_ECX_PKU(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  OSPKE                          = %s\n", CPUID_ECX_OSPKE(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  WAITPKG                        = %s\n", CPUID_ECX_WAITPKG(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512_VBMI2                   = %s\n", CPUID_ECX_AVX512_VBMI2(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  CET_SS (shadow stack)          = %s\n", CPUID_ECX_CET_SS(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  GFNI                           = %s\n", CPUID_ECX_GFNI(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  VAES                           = %s\n", CPUID_ECX_VAES(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  VPCLMULQDQ                     = %s\n", CPUID_ECX_VPCLMULQDQ(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512_VNNI                    = %s\n", CPUID_ECX_AVX512_VNNI(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512_BITALG                  = %s\n", CPUID_ECX_AVX512_BITALG(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  TME_EN                         = %s\n", CPUID_ECX_TME_EN(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512_VPOPCNTDQ               = %s\n", CPUID_ECX_AVX512_VPOPCNTDQ(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  LA57 (5-level paging)          = %s\n", CPUID_ECX_LA57(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  MAWAU (BNDLDX/BNDSTX)          = %u (NOT BOOLEAN)\n", CPUID_ECX_MAWAU(CpuidPacket->ECX));
                        ShowMessages("  RDPID                          = %s\n", CPUID_ECX_RDPID(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  KL (Key Locker)                = %s\n", CPUID_ECX_KL(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  CLDEMOTE                       = %s\n", CPUID_ECX_CLDEMOTE(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  MOVDIRI                        = %s\n", CPUID_ECX_MOVDIRI(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  MOVDIR64B                      = %s\n", CPUID_ECX_MOVDIR64B(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  SGX_LC (Launch Config)         = %s\n", CPUID_ECX_SGX_LC(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  PKS                            = %s\n\n", CPUID_ECX_PKS(CpuidPacket->ECX) ? "TRUE" : "FALSE");

                        //
                        // EDX
                        //
                        ShowMessages("-- EDX --\n\n");
                        ShowMessages("  AVX512_4VNNIW (Xeon Phi only)  = %s\n", CPUID_EDX_AVX512_4VNNIW(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512_4FMAPS (Xeon Phi only)  = %s\n", CPUID_EDX_AVX512_4FMAPS(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  Fast Short REP MOV             = %s\n", CPUID_EDX_FAST_SHORT_REP_MOV(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVX512_VP2INTERSECT            = %s\n", CPUID_EDX_AVX512_VP2INTERSECT(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  MD_CLEAR                       = %s\n", CPUID_EDX_MD_CLEAR(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  SERIALIZE                      = %s\n", CPUID_EDX_SERIALIZE(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  Hybrid part                    = %s\n", CPUID_EDX_HYBRID(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  PCONFIG                        = %s\n", CPUID_EDX_PCONFIG(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  CET_IBT (branch tracking)      = %s\n", CPUID_EDX_CET_IBT(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  IBRS/IBPB                      = %s\n", CPUID_EDX_IBRS_IBPB(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  STIBP                          = %s\n", CPUID_EDX_STIBP(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  L1D_FLUSH                      = %s\n", CPUID_EDX_L1D_FLUSH(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  IA32_ARCH_CAPABILITIES MSR     = %s\n", CPUID_EDX_IA32_ARCH_CAPABILITIES(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  IA32_CORE_CAPABILITIES MSR     = %s\n", CPUID_EDX_IA32_CORE_CAPABILITIES(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                        ShowMessages("  SSBD                           = %s\n\n", CPUID_EDX_SSBD(CpuidPacket->EDX) ? "TRUE" : "FALSE");
                    }
                    else
                    {
                        //
                        // This header only defines the EBX/ECX/EDX bitfield layout for sub-leaf
                        // (ECX) = 0. If the processor reports further sub-leaves, decoding them
                        // with the sub-leaf-0 struct would silently misinterpret the bits, so
                        // instead their raw dwords are printed undecoded - consistent with this
                        // file's rule of only reading a field through a macro that's actually
                        // defined for it.
                        //
                        ShowMessages("  No bitfield macros are defined for these in ia32.h, so their\n");
                        ShowMessages("  raw dwords are shown without decoding:\n");
                        ShowMessages("    ECX=%u: EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\n\n",
                                     SubFunctionId,
                                     CpuidPacket->EAX,
                                     CpuidPacket->EBX,
                                     CpuidPacket->ECX,
                                     CpuidPacket->EDX);
                    }

                    break;

                case 0x8:
                    ShowMessages("==== CPUID.(EAX=08H) ====\n\n");
                    ShowMessages("  This leaf is reserved/not implemented on modern processors.\n");
                    ShowMessages("  (Was previously used for Processor Serial Number on some CPUs)\n\n");
                    ShowMessages("  Raw data:\n");
                    ShowMessages("  EAX: 0x%08X\n", CpuidPacket->EAX);
                    ShowMessages("  EBX: 0x%08X\n", CpuidPacket->EBX);
                    ShowMessages("  ECX: 0x%08X\n", CpuidPacket->ECX);
                    ShowMessages("  EDX: 0x%08X\n", CpuidPacket->EDX);
                    break;

                case 0x9:
                    ShowMessages("==== CPUID.(EAX=09H) Direct Cache Access Information ====\n\n");

                    ShowMessages("  *******************************************************\n"
                                 "  *               LEAF 9 HAS NO SUBLEAVES               *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    //
                    // EAX mirrors IA32_PLATFORM_DCA_CAP[31:0] verbatim. ia32.h doesn't split
                    // it into sub-fields here (those bit meanings live in the MSR's own
                    // spec, not in this CPUID leaf), so it's read through its single
                    // whole-dword macro and shown as raw hex rather than decoded further.
                    //
                    ShowMessages("  IA32_PLATFORM_DCA_CAP (EAX, mirrors MSR 1F8H) = 0x%08X\n",
                                 CPUID_EAX_IA32_PLATFORM_DCA_CAP(CpuidPacket->EAX));

                    //
                    // EBX/ECX/EDX are fully reserved for this leaf.
                    //
                    ShowMessages("  Reserved (EBX) = 0x%08X\n", CPUID_EBX_RESERVED(CpuidPacket->EBX));
                    ShowMessages("  Reserved (ECX) = 0x%08X\n", CPUID_ECX_RESERVED(CpuidPacket->ECX));
                    ShowMessages("  Reserved (EDX) = 0x%08X\n\n", CPUID_EDX_RESERVED(CpuidPacket->EDX));

                    break;

                case 0xA:
                    ShowMessages("==== CPUID.(EAX=0AH) Architectural Performance Monitoring Leaf ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *               LEAF 10 HAS NO SUBLEAVES              *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    if (CPUID_EAX_VERSION_ID_OF_ARCHITECTURAL_PERFORMANCE_MONITORING(CpuidPacket->EAX) == 0)
                    {
                        //
                        // Per the spec: architectural perfmon is only supported if VersionId > 0.
                        // At version 0 the rest of this leaf isn't architecturally meaningful, so stop here
                        //
                        ShowMessages("  VersionId = 0 -> architectural performance monitoring not supported;\n"
                                     "  remaining fields in this leaf are not architecturally defined.\n\n");

                        break;
                    }

                    //
                    // EAX
                    //
                    ShowMessages("-- EAX --\n\n");
                    ShowMessages("  VersionId                               = %u\n",
                                 CPUID_EAX_VERSION_ID_OF_ARCHITECTURAL_PERFORMANCE_MONITORING(CpuidPacket->EAX));
                    ShowMessages("  NumberOfCountersPerLogicalProcessor     = %u\n",
                                 CPUID_EAX_NUMBER_OF_PERFORMANCE_MONITORING_COUNTER_PER_LOGICAL_PROCESSOR(CpuidPacket->EAX));
                    ShowMessages("  BitWidthOfPerformanceMonitoringCounter  = %u\n",
                                 CPUID_EAX_BIT_WIDTH_OF_PERFORMANCE_MONITORING_COUNTER(CpuidPacket->EAX));
                    ShowMessages("  EbxBitVectorLength                      = %u\n\n",
                                 CPUID_EAX_EBX_BIT_VECTOR_LENGTH(CpuidPacket->EAX));

                    //
                    // EBX
                    //
                    ShowMessages("-- EBX (bit = 1 means the event is NOT available) --\n\n");
                    ShowMessages("  CoreCycleEventNotAvailable                = %u\n",
                                 CPUID_EBX_CORE_CYCLE_EVENT_NOT_AVAILABLE(CpuidPacket->EBX));
                    ShowMessages("  InstructionRetiredEventNotAvailable       = %u\n",
                                 CPUID_EBX_INSTRUCTION_RETIRED_EVENT_NOT_AVAILABLE(CpuidPacket->EBX));
                    ShowMessages("  ReferenceCyclesEventNotAvailable          = %u\n",
                                 CPUID_EBX_REFERENCE_CYCLES_EVENT_NOT_AVAILABLE(CpuidPacket->EBX));
                    ShowMessages("  LastLevelCacheReferenceEventNotAvailable  = %u\n",
                                 CPUID_EBX_LAST_LEVEL_CACHE_REFERENCE_EVENT_NOT_AVAILABLE(CpuidPacket->EBX));
                    ShowMessages("  LastLevelCacheMissesEventNotAvailable     = %u\n",
                                 CPUID_EBX_LAST_LEVEL_CACHE_MISSES_EVENT_NOT_AVAILABLE(CpuidPacket->EBX));
                    ShowMessages("  BranchInstructionRetiredEventNotAvailable = %u\n",
                                 CPUID_EBX_BRANCH_INSTRUCTION_RETIRED_EVENT_NOT_AVAILABLE(CpuidPacket->EBX));
                    ShowMessages("  BranchMispredictRetiredEventNotAvailable  = %u\n\n",
                                 CPUID_EBX_BRANCH_MISPREDICT_RETIRED_EVENT_NOT_AVAILABLE(CpuidPacket->EBX));

                    if (CPUID_EAX_EBX_BIT_VECTOR_LENGTH(CpuidPacket->EAX) < 7)
                    {
                        ShowMessages("  NOTE: EbxBitVectorLength=%u (<7): bits at/after this length are not\n"
                                     "        architecturally defined on this CPU; treat them as unreliable.\n",
                                     CPUID_EAX_EBX_BIT_VECTOR_LENGTH(CpuidPacket->EAX));
                    }

                    //
                    // ECX
                    //
                    ShowMessages("-- ECX --\n\n");
                    ShowMessages("  Reserved                                   = 0x%08X\n\n",
                                 CPUID_ECX_RESERVED(CpuidPacket->ECX));

                    //
                    // EDX: fixed-function counter fields only defined if VersionId > 1
                    //
                    ShowMessages("-- EDX --\n\n");
                    if (CPUID_EAX_VERSION_ID_OF_ARCHITECTURAL_PERFORMANCE_MONITORING(CpuidPacket->EAX) > 1)
                    {
                        ShowMessages("  NumberOfFixedFunctionPerformanceCounters   = %u\n",
                                     CPUID_EDX_NUMBER_OF_FIXED_FUNCTION_PERFORMANCE_COUNTERS(CpuidPacket->EDX));
                        ShowMessages("  BitWidthOfFixedFunctionPerformanceCounters = %u\n\n",
                                     CPUID_EDX_BIT_WIDTH_OF_FIXED_FUNCTION_PERFORMANCE_COUNTERS(CpuidPacket->EDX));
                    }
                    else
                    {
                        ShowMessages("  NOTE: VersionId=%u (<=1): fixed-function counter fields are not\n",
                                     CPUID_EAX_VERSION_ID_OF_ARCHITECTURAL_PERFORMANCE_MONITORING(CpuidPacket->EAX));
                        ShowMessages("        architecturally defined; showing raw macro output anyway:\n");
                        ShowMessages("  NumberOfFixedFunctionPerformanceCounters   = %u (undefined)\n",
                                     CPUID_EDX_NUMBER_OF_FIXED_FUNCTION_PERFORMANCE_COUNTERS(CpuidPacket->EDX));
                        ShowMessages("  BitWidthOfFixedFunctionPerformanceCounters = %u (undefined)\n",
                                     CPUID_EDX_BIT_WIDTH_OF_FIXED_FUNCTION_PERFORMANCE_COUNTERS(CpuidPacket->EDX));
                    }

                    ShowMessages("  AnyThreadDeprecation                       = %s\n\n",
                                 CPUID_EDX_ANY_THREAD_DEPRECATION(CpuidPacket->EDX) ? "TRUE" : "FALSE");

                    break;

                case 0xB:

                    //
                    // Check if this leaf is supported or not
                    //
                    if (!CpuidPacket->LeafBSupported)
                    {
                        ShowMessages("==== CPUID.(EAX=0BH) Extended Topology Enumeration ====\n");
                        ShowMessages("  Leaf presence check failed: CPUID.0BH:EBX[15:0] == 0 at sub-leaf 0.\n"
                                     "  This processor does not implement leaf 0BH (consider leaf 1FH instead).\n\n");
                        break;
                    }
                    ShowMessages("==== CPUID.(EAX=0BH) Extended Topology Enumeration ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *             Max NumberOfSubLeaves = %u               *\n"
                                 "  *******************************************************\n\n",
                                 CpuidPacket->LeafBMaxSubleaf);

                    switch (CPUID_ECX_LEVEL_TYPE(CpuidPacket->ECX))
                    {
                    case 0:
                        TypeName = "Invalid";
                        break;
                    case 1:
                        TypeName = "SMT (Hyper-Threading)";
                        break;
                    case 2:
                        TypeName = "Core";
                        break;
                    default:
                        TypeName = "Reserved";
                        break;
                    }

                    ShowMessages("---- CPUID.(EAX=0BH, ECX=%u) ----\n\n", SubFunctionId);

                    //
                    // ECX: Level number and type
                    //
                    ShowMessages("-- ECX --\n\n");
                    ShowMessages("  LevelNumber (echoes ECX input) = %u\n",
                                 CPUID_ECX_LEVEL_NUMBER(CpuidPacket->ECX));
                    ShowMessages("  LevelType                      = %u (%s)\n\n",
                                 CPUID_ECX_LEVEL_TYPE(CpuidPacket->ECX),
                                 TypeName);
                    //
                    // EAX: Shift count
                    //
                    ShowMessages("-- EAX --\n\n");
                    ShowMessages("  X2ApicIdToUniqueTopologyIdShift = %u\n\n",
                                 CPUID_EAX_X2APIC_ID_TO_UNIQUE_TOPOLOGY_ID_SHIFT(CpuidPacket->EAX));

                    //
                    // EBX: Number of logical processors (diagnostic only)
                    //
                    ShowMessages("-- EBX --\n\n");
                    ShowMessages("  NumberOfLogicalProcessorsAtThisLevelType = %u (DIAGNOSTIC ONLY - do not use for topology enumeration)\n\n",
                                 CPUID_EBX_NUMBER_OF_LOGICAL_PROCESSORS_AT_THIS_LEVEL_TYPE(CpuidPacket->EBX));

                    //
                    // EDX: x2APIC ID (constant across all sub-leaves)
                    //
                    ShowMessages("-- EDX --\n\n");
                    ShowMessages("  X2ApicId (current logical processor) = %u\n\n",
                                 CPUID_EDX_X2APIC_ID(CpuidPacket->EDX));

                    break;

                case 0xC:
                    ShowMessages("==== CPUID.(EAX=0CH) ====\n\n");
                    ShowMessages("  This leaf is reserved (not implemented).\n\n");
                    ShowMessages("  Raw data:\n");
                    ShowMessages("  EAX: 0x%08X\n", CpuidPacket->EAX);
                    ShowMessages("  EBX: 0x%08X\n", CpuidPacket->EBX);
                    ShowMessages("  ECX: 0x%08X\n", CpuidPacket->ECX);
                    ShowMessages("  EDX: 0x%08X\n\n", CpuidPacket->EDX);
                    break;

                case 0xD:
                    ShowMessages("==== CPUID.(EAX=0DH) Processor Extended State Enumeration ====\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *             Max NumberOfSubLeaves = 62              *\n"
                                 "  *******************************************************\n\n");

                    if (SubFunctionId == 0)
                    {
                        ShowMessages("-- EAX (XCR0 lower 32 bits) --\n\n");
                        ShowMessages("  X87State (bit 0)               = %s\n", CPUID_EAX_X87_STATE(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                        ShowMessages("  SSEState (bit 1)               = %s\n", CPUID_EAX_SSE_STATE(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                        ShowMessages("  AVXState (bit 2)               = %s\n", CPUID_EAX_AVX_STATE(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                        ShowMessages("  MPXState (bits 4:3)            = %u\n", CPUID_EAX_MPX_STATE(CpuidPacket->EAX));
                        ShowMessages("  AVX512State (bits 7:5)         = %u\n", CPUID_EAX_AVX_512_STATE(CpuidPacket->EAX));
                        ShowMessages("  UsedForIa32Xss1 (bit 8)        = %s\n", CPUID_EAX_USED_FOR_IA32_XSS_1(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                        ShowMessages("  PKRUState (bit 9)              = %s\n", CPUID_EAX_PKRU_STATE(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                        ShowMessages("  UsedForIa32Xss2 (bit 13)       = %s\n\n", CPUID_EAX_USED_FOR_IA32_XSS_2(CpuidPacket->EAX) ? "TRUE" : "FALSE");

                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  MaxSizeRequiredByEnabledFeaturesInXcr0 = %u bytes\n\n",
                                     CPUID_EBX_MAX_SIZE_REQUIRED_BY_ENABLED_FEATURES_IN_XCR0(CpuidPacket->EBX));

                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  MaxSizeOfXsaveXrstorSaveArea           = %u bytes\n\n",
                                     CPUID_ECX_MAX_SIZE_OF_XSAVE_XRSTOR_SAVE_AREA(CpuidPacket->ECX));
                        ShowMessages("-- EDX (XCR0 upper 32 bits) --\n\n");
                        ShowMessages("  Xcr0SupportedBits (bits 63:32 of XCR0) = 0x%08X\n\n",
                                     CPUID_EDX_XCR0_SUPPORTED_BITS(CpuidPacket->EDX));
                    }

                    else if (SubFunctionId == 1)
                    {
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  SupportsXsavecAndCompactedXrstor (XSAVEC) = %s\n",
                                     CPUID_EAX_SUPPORTS_XSAVEC_AND_COMPACTED_XRSTOR(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                        ShowMessages("  SupportsXgetbvWithEcx1                     = %s\n",
                                     CPUID_EAX_SUPPORTS_XGETBV_WITH_ECX_1(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                        ShowMessages("  SupportsXsaveXrstorAndIa32Xss (XSAVES)     = %s\n\n",
                                     CPUID_EAX_SUPPORTS_XSAVE_XRSTOR_AND_IA32_XSS(CpuidPacket->EAX) ? "TRUE" : "FALSE");

                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  SizeOfXsaveArea (XCR0 | IA32_XSS enabled) = %u bytes\n",
                                     CPUID_EBX_SIZE_OF_XSAVE_AREAD(CpuidPacket->EBX));

                        ShowMessages("-- ECX (IA32_XSS lower 32 bits) --\n\n");
                        ShowMessages("  UsedForXcr01 (bits 7:0)              = 0x%02X\n",
                                     CPUID_ECX_USED_FOR_XCR0_1(CpuidPacket->ECX));
                        ShowMessages("  PtState (bit 8)                      = %s\n",
                                     CPUID_ECX_PT_STATE(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  UsedForXcr02 (bit 9)                 = %s\n",
                                     CPUID_ECX_USED_FOR_XCR0_2(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  CetUserState (bit 11)                = %s\n",
                                     CPUID_ECX_CET_USER_STATE(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  CetSupervisorState (bit 12)          = %s\n",
                                     CPUID_ECX_CET_SUPERVISOR_STATE(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  HdcState (bit 13)                    = %s\n",
                                     CPUID_ECX_HDC_STATE(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  LbrState (bit 15)                    = %s\n",
                                     CPUID_ECX_LBR_STATE(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  HwpState (bit 16)                    = %s\n\n",
                                     CPUID_ECX_HWP_STATE(CpuidPacket->ECX) ? "TRUE" : "FALSE");

                        ShowMessages("-- EDX (IA32_XSS upper 32 bits) --\n\n");
                        ShowMessages("  SupportedUpperIa32XssBits (bits 63:32) = 0x%08X\n\n",
                                     CPUID_EDX_SUPPORTED_UPPER_IA32_XSS_BITS(CpuidPacket->EDX));
                    }

                    else if (SubFunctionId >= 2)
                    {
                        //
                        // Check if the user input is valid
                        // Need to check both XCR0 and IA32_XSS vectors
                        //
                        UINT64 ValidBits = CpuidPacket->XCR0Vector | CpuidPacket->IA32_XSS_Vector;

                        //
                        // Validate if this sub-leaf is supported
                        //
                        if (((ValidBits >> SubFunctionId) & (UINT64)1) == 0)
                        {
                            ShowMessages("  Sub-leaf %u is NOT supported on this CPU\n", SubFunctionId);
                            ShowMessages("  Valid sub-leaves are those with bits set in:\n");
                            ShowMessages("    XCR0 vector:     0x%016llX\n", (ULONG64)CpuidPacket->XCR0Vector);
                            ShowMessages("    IA32_XSS vector: 0x%016llX\n", (ULONG64)CpuidPacket->IA32_XSS_Vector);
                            ShowMessages("    Combined vector: 0x%016llX\n\n", (ULONG64)ValidBits);

                            break;
                        }

                        ShowMessages("-- State Component Information --\n\n");
                        ShowMessages("  SaveAreaSize (EAX)   = %u bytes\n",
                                     CPUID_EAX_IA32_PLATFORM_DCA_CAP(CpuidPacket->EAX));
                        ShowMessages("  SaveAreaOffset (EBX) = %u bytes\n",
                                     CPUID_EBX_RESERVED(CpuidPacket->EBX));
                        ShowMessages("  ManagedViaIa32Xss (ECX bit 0) = %u (%s)\n",
                                     CPUID_ECX_ECX_2(CpuidPacket->ECX),
                                     CPUID_ECX_ECX_2(CpuidPacket->ECX) ? "IA32_XSS" : "XCR0");
                        ShowMessages("  Aligned64ByteBoundary (ECX bit 1) = %u%s\n",
                                     CPUID_ECX_ECX_1(CpuidPacket->ECX),
                                     CPUID_ECX_ECX_1(CpuidPacket->ECX) ? " (next 64-byte boundary)" : " (immediately following)");
                        ShowMessages("  Reserved (EDX) = 0x%08X\n\n",
                                     CPUID_EDX_RESERVED(CpuidPacket->EDX));
                    }

                    break;

                case 0xE:
                    ShowMessages("==== CPUID.(EAX=0EH) ====\n\n");
                    ShowMessages("  This leaf is reserved (not implemented).\n\n");
                    ShowMessages("  Raw data:\n");
                    ShowMessages("  EAX: 0x%08X\n", CpuidPacket->EAX);
                    ShowMessages("  EBX: 0x%08X\n", CpuidPacket->EBX);
                    ShowMessages("  ECX: 0x%08X\n", CpuidPacket->ECX);
                    ShowMessages("  EDX: 0x%08X\n\n", CpuidPacket->EDX);
                    break;

                case 0xF: // 0xF = 15 (decimal); CPUID_INTEL_RESOURCE_DIRECTOR_TECHNOLOGY_MONITORING_INFORMATION
                    ShowMessages("==== CPUID.(EAX=0FH) Intel RDT Monitoring ====\n\n");
                    ShowMessages("  This leaf is not yet implemented in HyperDbg.\n");
                    ShowMessages("  (Intel Resource Director Technology - Monitoring)\n\n");
                    ShowMessages("  Raw data:\n");
                    ShowMessages("  EAX: 0x%08X\n", CpuidPacket->EAX);
                    ShowMessages("  EBX: 0x%08X\n", CpuidPacket->EBX);
                    ShowMessages("  ECX: 0x%08X\n", CpuidPacket->ECX);
                    ShowMessages("  EDX: 0x%08X\n\n", CpuidPacket->EDX);
                    break;

                case 0x10:
                    ShowMessages("==== CPUID.(EAX=10H, ECX=%u) Intel RDT Allocation Information ====\n\n", SubFunctionId);
                    ShowMessages("  *******************************************************\n"
                                 "  *             Max NumberOfSubLeaves = 3               *\n"
                                 "  *******************************************************\n\n");

                    if (SubFunctionId == 0)
                    {
                        //
                        // Resource type enumeration
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  Ia32PlatformDcaCap = 0x%08X\n\n",
                                     CPUID_EAX_IA32_PLATFORM_DCA_CAP(CpuidPacket->EAX));

                        //
                        // EBX
                        //
                        ShowMessages("-- EBX (Supported Allocation Types) --\n\n");
                        ShowMessages("  Raw value = 0x%08X\n", CpuidPacket->EBX);
                        ShowMessages("  L3 Cache Allocation (bit 1) = %s\n",
                                     CPUID_EBX_SUPPORTS_L3_CACHE_ALLOCATION_TECHNOLOGY(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  L2 Cache Allocation (bit 2) = %s\n",
                                     CPUID_EBX_SUPPORTS_L2_CACHE_ALLOCATION_TECHNOLOGY(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  Memory Bandwidth Allocation (bit 3) = %s\n\n",
                                     CPUID_EBX_SUPPORTS_MEMORY_BANDWIDTH_ALLOCATION(CpuidPacket->EBX) ? "TRUE" : "FALSE");

                        //
                        // ECX
                        //
                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n", CPUID_ECX_RESERVED(CpuidPacket->ECX));

                        //
                        // EDX
                        //
                        ShowMessages("-- EDX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EDX_RESERVED(CpuidPacket->EDX));
                    }

                    else if (SubFunctionId == 1)
                    {
                        //
                        // L3 cache allocation
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  LengthOfCapacityBitMask (minus-one) = %u (actual = %u bits)\n\n",
                                     CPUID_EAX_LENGTH_OF_CAPACITY_BIT_MASK(CpuidPacket->EAX),
                                     CPUID_EAX_LENGTH_OF_CAPACITY_BIT_MASK(CpuidPacket->EAX) + 1);

                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  Bit-granular map = 0x%08X\n\n", CPUID_EBX_EBX_0(CpuidPacket->EBX));

                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  CodeAndDataPriorizationTechnologySupported = %s%s\n\n",
                                     CPUID_ECX_CODE_AND_DATA_PRIORIZATION_TECHNOLOGY_SUPPORTED(CpuidPacket->ECX) ? "TRUE" : "FALSE",
                                     CPUID_ECX_CODE_AND_DATA_PRIORIZATION_TECHNOLOGY_SUPPORTED(CpuidPacket->ECX) ? " (CDP supported)" : "");

                        ShowMessages("-- EDX --\n\n");
                        ShowMessages("  HighestCosNumberSupported = %u (actual = %u COS)\n\n",
                                     CPUID_EDX_HIGHEST_COS_NUMBER_SUPPORTED(CpuidPacket->EDX),
                                     CPUID_EDX_HIGHEST_COS_NUMBER_SUPPORTED(CpuidPacket->EDX) + 1);
                    }

                    else if (SubFunctionId == 2)
                    {
                        //
                        // Sub-leaf 2 (L2 Cache Allocation)
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  LengthOfCapacityBitMask (minus-one) = %u (actual = %u bits)\n\n",
                                     CPUID_EAX_LENGTH_OF_CAPACITY_BIT_MASK(CpuidPacket->EAX),
                                     CPUID_EAX_LENGTH_OF_CAPACITY_BIT_MASK(CpuidPacket->EAX) + 1);

                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  Bit-granular map = 0x%08X\n\n", CPUID_EBX_EBX_0(CpuidPacket->EBX));

                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n", CPUID_ECX_RESERVED(CpuidPacket->ECX));

                        ShowMessages("-- EDX --\n\n");
                        ShowMessages("  HighestCosNumberSupported = %u (actual = %u COS)\n\n",
                                     CPUID_EDX_HIGHEST_COS_NUMBER_SUPPORTED(CpuidPacket->EDX),
                                     CPUID_EDX_HIGHEST_COS_NUMBER_SUPPORTED(CpuidPacket->EDX) + 1);
                    }

                    else if (SubFunctionId == 3)
                    {
                        //
                        // Sub-leaf 3 (Memory Bandwidth Allocation)
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  MaxMbaThrottlingValue (minus-one) = %u (actual = %u)\n\n",
                                     CPUID_EAX_MAX_MBA_THROTTLING_VALUE(CpuidPacket->EAX),
                                     CPUID_EAX_MAX_MBA_THROTTLING_VALUE(CpuidPacket->EAX) + 1);

                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EBX_RESERVED(CpuidPacket->EBX));

                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  ResponseOfDelayIsLinear = %s%s\n",
                                     CPUID_ECX_RESPONSE_OF_DELAY_IS_LINEAR(CpuidPacket->ECX) ? "TRUE" : "FALSE",
                                     CPUID_ECX_RESPONSE_OF_DELAY_IS_LINEAR(CpuidPacket->ECX) ? " (linear response)" : " (non-linear)\n\n");

                        ShowMessages("-- EDX --\n\n");
                        ShowMessages("  HighestCosNumberSupported = %u (actual = %u COS)\n\n",
                                     CPUID_EDX_HIGHEST_COS_NUMBER_SUPPORTED(CpuidPacket->EDX),
                                     CPUID_EDX_HIGHEST_COS_NUMBER_SUPPORTED(CpuidPacket->EDX) + 1);
                    }

                    else
                    {
                        ShowMessages("  Sub-leaf %u is NOT supported on this CPU\n", SubFunctionId);
                        ShowMessages("  raw bytes: EAX = %u\n  EBX = %u\n  ECX = %u\n  EDX = %u\n\n",
                                     CpuidPacket->EAX,
                                     CpuidPacket->EBX,
                                     CpuidPacket->ECX,
                                     CpuidPacket->EDX);
                    }

                    break;

                case 0x11:
                    ShowMessages("==== CPUID.(EAX=11H) ====\n\n");
                    ShowMessages("  This leaf is reserved (not implemented).\n\n");
                    ShowMessages("  Raw data:\n");
                    ShowMessages("  EAX: 0x%08X\n", CpuidPacket->EAX);
                    ShowMessages("  EBX: 0x%08X\n", CpuidPacket->EBX);
                    ShowMessages("  ECX: 0x%08X\n", CpuidPacket->ECX);
                    ShowMessages("  EDX: 0x%08X\n\n", CpuidPacket->EDX);
                    break;

                case 0x12:
                {
                    //
                    // SGX, not DAT. 0x12 = 18 (decimal)
                    //
                    ShowMessages("==== CPUID.(EAX=12H) Intel SGX Information ====\n\n");

                    if (!CpuidPacket->Leaf12Supported)
                    {
                        ShowMessages("  SGX is not supported on this CPU (CPUID.7H:EBX[2] = 0).\n\n");
                        break;
                    }

                    ShowMessages("  *******************************************************\n"
                                 "  *             Max NumberOfSubLeaves = %u               *\n"
                                 "  *******************************************************\n\n",
                                 CpuidPacket->Leaf12MaxSubLeaf);

                    if (SubFunctionId == 0)
                    {
                        //
                        // SGX capabilities
                        //
                        ShowMessages("-- EAX (SGX Capabilities) --\n\n");
                        ShowMessages("  SGX1 Support (bit 0)           = %s\n",
                                     CPUID_EAX_SGX1(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                        ShowMessages("  SGX2 Support (bit 1)           = %s\n",
                                     CPUID_EAX_SGX2(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                        ShowMessages("  ENCLV Advanced (bit 5)         = %s\n",
                                     CPUID_EAX_SGX_ENCLV_ADVANCED(CpuidPacket->EAX) ? "TRUE" : "FALSE");
                        ShowMessages("  ENCLS Advanced (bit 6)         = %s\n\n",
                                     CPUID_EAX_SGX_ENCLS_ADVANCED(CpuidPacket->EAX) ? "TRUE" : "FALSE");

                        ShowMessages("-- EBX (MISCSELECT - Extended SGX Features) --\n\n");
                        ShowMessages("  Miscselect = 0x%08X\n\n",
                                     CPUID_EBX_MISCSELECT(CpuidPacket->EBX));

                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n",
                                     CPUID_ECX_RESERVED(CpuidPacket->ECX));

                        ShowMessages("-- EDX (Maximum Enclave Sizes) --\n\n");
                        ShowMessages("  MaxEnclaveSizeNot64 = %u (2^%u = %llu bytes)\n",
                                     CPUID_EDX_MAX_ENCLAVE_SIZE_NOT64(CpuidPacket->EDX),
                                     CPUID_EDX_MAX_ENCLAVE_SIZE_NOT64(CpuidPacket->EDX),
                                     (ULONG64)(1ULL << CPUID_EDX_MAX_ENCLAVE_SIZE_NOT64(CpuidPacket->EDX)));
                        ShowMessages("  MaxEnclaveSize64     = %u (2^%u = %llu bytes)\n\n",
                                     CPUID_EDX_MAX_ENCLAVE_SIZE_64(CpuidPacket->EDX),
                                     CPUID_EDX_MAX_ENCLAVE_SIZE_64(CpuidPacket->EDX),
                                     (ULONG64)(1ULL << CPUID_EDX_MAX_ENCLAVE_SIZE_64(CpuidPacket->EDX)));
                    }

                    else if (SubFunctionId == 1)
                    {
                        //
                        // SGX attributes
                        //
                        ShowMessages("-- EAX (SECS.ATTRIBUTES[31:0]) --\n\n");
                        ShowMessages("  ValidSecsAttributes0 = 0x%08X\n\n",
                                     CPUID_EAX_VALID_SECS_ATTRIBUTES_0(CpuidPacket->EAX));

                        ShowMessages("-- EBX (SECS.ATTRIBUTES[63:32]) --\n\n");
                        ShowMessages("  ValidSecsAttributes1 = 0x%08X\n\n",
                                     CPUID_EBX_VALID_SECS_ATTRIBUTES_1(CpuidPacket->EBX));

                        ShowMessages("-- ECX (SECS.ATTRIBUTES[95:64]) --\n\n");
                        ShowMessages("  ValidSecsAttributes2 = 0x%08X\n\n",
                                     CPUID_ECX_VALID_SECS_ATTRIBUTES_2(CpuidPacket->ECX));

                        ShowMessages("-- EDX (SECS.ATTRIBUTES[127:96]) --\n\n");
                        ShowMessages("  ValidSecsAttributes3 = 0x%08X\n\n",
                                     CPUID_EDX_VALID_SECS_ATTRIBUTES_3(CpuidPacket->EDX));
                    }

                    else
                    {
                        //
                        // Subleaf 2+ (EPC sections)
                        //
                        if (CPUID_EAX_SUB_LEAF_TYPE(CpuidPacket->EAX) == 0)
                        {
                            //
                            // Type 0: invalid subleaf
                            //
                            ShowMessages("-- EAX --\n\n");
                            ShowMessages("  SubLeafType = %u (Invalid - no EPC section)\n",
                                         CPUID_EAX_SUB_LEAF_TYPE(CpuidPacket->EAX));

                            ShowMessages("\n-- EBX --\n");
                            ShowMessages("  Zero = 0x%08X\n", CPUID_EBX_ZERO(CpuidPacket->EBX));

                            ShowMessages("\n-- ECX --\n");
                            ShowMessages("  Zero = 0x%08X\n", CPUID_ECX_ZERO(CpuidPacket->ECX));

                            ShowMessages("\n-- EDX --\n");
                            ShowMessages("  Zero = 0x%08X\n", CPUID_EDX_ZERO(CpuidPacket->EDX));
                        }

                        else if (CPUID_EAX_SUB_LEAF_TYPE(CpuidPacket->EAX) == 1)
                        {
                            //
                            // Reconstruct base address from EAX and EBX
                            //
                            UINT64 BaseLow     = (UINT64)CPUID_EAX_EPC_BASE_PHYSICAL_ADDRESS_1(CpuidPacket->EAX);
                            UINT64 BaseHigh    = (UINT64)CPUID_EBX_EPC_BASE_PHYSICAL_ADDRESS_2(CpuidPacket->EBX);
                            UINT64 BaseAddress = (BaseHigh << 32) | (BaseLow << 12);

                            //
                            // Reconstruct size from ECX and EDX
                            //
                            UINT64 SizeLow   = (UINT64)CPUID_ECX_EPC_SIZE_1(CpuidPacket->ECX);
                            UINT64 SizeHigh  = (UINT64)CPUID_EDX_EPC_SIZE_2(CpuidPacket->EDX);
                            UINT64 SizeBytes = (SizeHigh << 32) | (SizeLow << 12);

                            ShowMessages("-- EAX --\n\n");
                            ShowMessages("  SubLeafType = %u (EPC Section)\n",
                                         CPUID_EAX_SUB_LEAF_TYPE(CpuidPacket->EAX));
                            ShowMessages("  EpcBasePhysicalAddress1 (bits 31:12) = 0x%05X\n\n",
                                         CPUID_EAX_EPC_BASE_PHYSICAL_ADDRESS_1(CpuidPacket->EAX));

                            ShowMessages("-- EBX --\n\n");
                            ShowMessages("  EpcBasePhysicalAddress2 (bits 51:32) = 0x%05X\n\n",
                                         CPUID_EBX_EPC_BASE_PHYSICAL_ADDRESS_2(CpuidPacket->EBX));

                            ShowMessages("-- ECX --\n\n");
                            ShowMessages("  EpcSectionProperty = %u",
                                         CPUID_ECX_EPC_SECTION_PROPERTY(CpuidPacket->ECX));
                            switch (CPUID_ECX_EPC_SECTION_PROPERTY(CpuidPacket->ECX))
                            {
                            case 0:
                                ShowMessages(" (No confidentiality/integrity)\n\n");
                                break;
                            case 1:
                                ShowMessages(" (Confidentiality and integrity protection)\n\n");
                                break;
                            default:
                                ShowMessages(" (Reserved)\n\n");
                                break;
                            }
                            ShowMessages("  EpcSize1 (bits 31:12) = 0x%05X\n\n",
                                         CPUID_ECX_EPC_SIZE_1(CpuidPacket->ECX));

                            ShowMessages("-- EDX --\n\n");
                            ShowMessages("  EpcSize2 (bits 51:32) = 0x%05X\n\n",
                                         CPUID_EDX_EPC_SIZE_2(CpuidPacket->EDX));

                            ShowMessages("-- EPC Section Information --\n\n");
                            ShowMessages("  Base Address = 0x%016llX\n", (ULONG64)BaseAddress);
                            ShowMessages("  Size         = 0x%016llX bytes (%llu MB)\n\n",
                                         (ULONG64)SizeBytes,
                                         (ULONG64)(SizeBytes / (1024 * 1024)));
                        }

                        else
                        {
                            //
                            // Unknown subleaf type (reserved)
                            //
                            ShowMessages("-- Raw Data for Sub-leaf %u (Type %u) --\n\n",
                                         SubFunctionId,
                                         CPUID_EAX_SUB_LEAF_TYPE(CpuidPacket->EAX));

                            ShowMessages("  EAX = 0x%08X\n", CpuidPacket->EAX);
                            ShowMessages("  EBX = 0x%08X\n", CpuidPacket->EBX);
                            ShowMessages("  ECX = 0x%08X\n", CpuidPacket->ECX);
                            ShowMessages("  EDX = 0x%08X\n\n", CpuidPacket->EDX);
                            ShowMessages("  Note: Reserved sub-leaf type. Please refer to the latest Intel SDM.\n\n");
                        }
                    }

                    break;
                }

                case 0x13:
                    ShowMessages("==== CPUID.(EAX=13H) ====\n\n");
                    ShowMessages("  This leaf is reserved (not implemented).\n\n");
                    ShowMessages("  Raw data:\n");
                    ShowMessages("  EAX: 0x%08X\n", CpuidPacket->EAX);
                    ShowMessages("  EBX: 0x%08X\n", CpuidPacket->EBX);
                    ShowMessages("  ECX: 0x%08X\n", CpuidPacket->ECX);
                    ShowMessages("  EDX: 0x%08X\n\n", CpuidPacket->EDX);
                    break;

                case 0x14:
                    ShowMessages("==== CPUID.(EAX=14H) Intel Processor Trace Information ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *             Max NumberOfSubLeaves = %u               *\n"
                                 "  *******************************************************\n\n",
                                 CpuidPacket->LeafEaxMaxSubleaf);

                    ShowMessages("==== CPUID.(EAX=14H, ECX=%u) Intel Processor Trace Information ====\n\n", SubFunctionId);

                    if (SubFunctionId == 0)
                    {
                        //
                        // main leaf
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  MaxSubLeaf = %u\n\n",
                                     CPUID_EAX_MAX_SUB_LEAF(CpuidPacket->EAX));

                        ShowMessages("-- EBX (Supported Features) --\n\n");
                        ShowMessages("  CR3Filter support (bit 0)                    = %s\n",
                                     CPUID_EBX_FLAG0(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  Configurable PSB & Cycle-Accurate (bit 1)    = %s\n",
                                     CPUID_EBX_FLAG1(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  IP Filtering & TraceStop (bit 2)             = %s\n",
                                     CPUID_EBX_FLAG2(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  MTC & COFI suppression (bit 3)               = %s\n",
                                     CPUID_EBX_FLAG3(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  PTWRITE support (bit 4)                      = %s\n",
                                     CPUID_EBX_FLAG4(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  Power Event Trace (bit 5)                    = %s\n",
                                     CPUID_EBX_FLAG5(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  PSB/PMI preservation (bit 6)                 = %s\n",
                                     CPUID_EBX_FLAG6(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  Event Trace (bit 7)                          = %s\n",
                                     CPUID_EBX_FLAG7(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  Disable TNT (bit 8)                          = %s\n\n",
                                     CPUID_EBX_FLAG8(CpuidPacket->EBX) ? "TRUE" : "FALSE");

                        ShowMessages("-- ECX (Output Schemes) --\n\n");
                        ShowMessages("  ToPA output scheme (bit 0)                   = %s\n",
                                     CPUID_ECX_FLAG0(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  ToPA tables with any entries (bit 1)         = %s\n",
                                     CPUID_ECX_FLAG1(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  Single-Range Output scheme (bit 2)           = %s\n",
                                     CPUID_ECX_FLAG2(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  Trace Transport subsystem (bit 3)            = %s\n",
                                     CPUID_ECX_FLAG3(CpuidPacket->ECX) ? "TRUE" : "FALSE");
                        ShowMessages("  LIP values include CS base (bit 31)          = %s\n\n",
                                     CPUID_ECX_FLAG31(CpuidPacket->ECX) ? "TRUE" : "FALSE");

                        ShowMessages("-- EDX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n",
                                     CPUID_EDX_RESERVED(CpuidPacket->EDX));
                    }

                    else if (SubFunctionId == 1)
                    {
                        //
                        // Packet generation
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  NumberOfConfigurableAddressRangesForFiltering = %u\n",
                                     CPUID_EAX_NUMBER_OF_CONFIGURABLE_ADDRESS_RANGES_FOR_FILTERING(CpuidPacket->EAX));
                        ShowMessages("  BitmapOfSupportedMtcPeriodEncodings          = 0x%04X\n\n",
                                     CPUID_EAX_BITMAP_OF_SUPPORTED_MTC_PERIOD_ENCODINGS(CpuidPacket->EAX));

                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  BitmapOfSupportedCycleThresholdValueEncodings = 0x%04X\n",
                                     CPUID_EBX_BITMAP_OF_SUPPORTED_CYCLE_THRESHOLD_VALUE_ENCODINGS(CpuidPacket->EBX));
                        ShowMessages("  BitmapOfSupportedConfigurablePsbFrequencyEncodings = 0x%04X\n\n",
                                     CPUID_EBX_BITMAP_OF_SUPPORTED_CONFIGURABLE_PSB_FREQUENCY_ENCODINGS(CpuidPacket->EBX));

                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n",
                                     CPUID_ECX_RESERVED(CpuidPacket->ECX));

                        ShowMessages("-- EDX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n",
                                     CPUID_EDX_RESERVED(CpuidPacket->EDX));
                    }

                    else
                    {
                        //
                        // Subleaves > 1 (if they exist)
                        //
                        ShowMessages("-- Raw Data for Sub-leaf %u --\n\n", SubFunctionId);
                        ShowMessages("  EAX = 0x%08X\n", CpuidPacket->EAX);
                        ShowMessages("  EBX = 0x%08X\n", CpuidPacket->EBX);
                        ShowMessages("  ECX = 0x%08X\n", CpuidPacket->ECX);
                        ShowMessages("  EDX = 0x%08X\n\n", CpuidPacket->EDX);
                        ShowMessages("  Note: This sub-leaf may be for future Intel PT features.\n");
                        ShowMessages("  Please refer to the latest Intel SDM for interpretation.\n\n");
                    }

                    break;

                case 0x15:
                {
                    ShowMessages("==== CPUID.(EAX=15H) TSC and Core Crystal Clock Information ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *               LEAF 15h HAS NO SUBLEAVES             *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");
                    //
                    // EAX: Denominator
                    //
                    UINT32 Denominator = CPUID_EAX_DENOMINATOR(CpuidPacket->EAX);
                    ShowMessages("-- EAX --\n\n");
                    ShowMessages("  Denominator = %u\n\n", Denominator);

                    //
                    // EBX: Numerator
                    //
                    UINT32 Numerator = CPUID_EBX_NUMERATOR(CpuidPacket->EBX);
                    ShowMessages("-- EBX --\n\n");
                    ShowMessages("  Numerator = %u\n\n", Numerator);

                    //
                    // ECX: Nominal frequency (if available)
                    //
                    UINT32 NominalFreq = CPUID_ECX_NOMINAL_FREQUENCY(CpuidPacket->ECX);
                    ShowMessages("-- ECX --\n\n");
                    ShowMessages("  NominalFrequency = %u Hz", NominalFreq);
                    if (NominalFreq > 0)
                    {
                        ShowMessages(" (%u MHz, %u GHz)\n",
                                     NominalFreq / 1000000,
                                     NominalFreq / 1000000000);
                    }
                    else
                    {
                        ShowMessages("  (not enumerated)\n\n");
                    }

                    //
                    // EDX: reserved
                    //
                    ShowMessages("\n-- EDX --\n");
                    ShowMessages("  Reserved = 0x%08X\n",
                                 CPUID_EDX_RESERVED(CpuidPacket->EDX));

                    //
                    // Calculate and display TSC frequency if possible
                    //
                    ShowMessages("-- TSC Frequency Information --\n\n");

                    if (Denominator == 0 || Numerator == 0)
                    {
                        ShowMessages("  TSC ratio not enumerated (denominator or numerator is 0)\n\n");
                    }

                    else
                    {
                        ShowMessages("  TSC / Core Crystal Clock ratio = %u / %u\n",
                                     Numerator,
                                     Denominator);
                        ShowMessages("  TSC frequency = Core Crystal Clock * (%u/%u)\n",
                                     Numerator,
                                     Denominator);
                        if (NominalFreq > 0)
                        {
                            UINT64 TSCFreqHz = (UINT64)NominalFreq * Numerator / Denominator;
                            ShowMessages("  TSC frequency = %llu Hz (%llu MHz, %llu GHz)\n\n",
                                         (ULONG64)TSCFreqHz,
                                         (ULONG64)(TSCFreqHz / 1000000),
                                         (ULONG64)(TSCFreqHz / 1000000000));
                        }
                        else
                        {
                            ShowMessages("  TSC frequency cannot be calculated (nominal frequency not enumerated)\n\n");
                        }
                    }

                    break;
                }

                case 0x16:
                {
                    ShowMessages("==== CPUID.(EAX=16H) Processor Frequency Information ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *               LEAF 16h HAS NO SUBLEAVES             *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    //
                    // EAX: Processor base frequency
                    //
                    UINT32 BaseFreq = CPUID_EAX_PROCESOR_BASE_FREQUENCY_MHZ(CpuidPacket->EAX);
                    ShowMessages("-- EAX --\n\n");
                    if (BaseFreq == 0)
                    {
                        ShowMessages("  ProcessorBaseFrequencyMhz = 0 (not supported)\n\n");
                    }
                    else
                    {
                        ShowMessages("  ProcessorBaseFrequencyMhz = %u MHz\n", BaseFreq);
                    }

                    //
                    // EBX: Maximum frequency
                    //
                    UINT32 MaxFreq = CPUID_EBX_PROCESSOR_MAXIMUM_FREQUENCY_MHZ(CpuidPacket->EBX);
                    ShowMessages("-- EBX --\n\n");
                    if (MaxFreq == 0)
                    {
                        ShowMessages("  ProcessorMaximumFrequencyMhz = 0 (not supported)\n\n");
                    }
                    else
                    {
                        ShowMessages("  ProcessorMaximumFrequencyMhz = %u MHz\n", MaxFreq);
                    }

                    //
                    // ECX: Bus (reference) frequency
                    //
                    UINT32 BusFreq = CPUID_ECX_BUS_FREQUENCY_MHZ(CpuidPacket->ECX);
                    ShowMessages("-- ECX --\n\n");
                    if (BusFreq == 0)
                    {
                        ShowMessages("  BusFrequencyMhz = 0 (not supported)\n\n");
                    }
                    else
                    {
                        ShowMessages("  BusFrequencyMhz = %u MHz\n\n", BusFreq);
                    }

                    //
                    // EDX: reserved
                    //
                    ShowMessages("-- EDX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n",
                                 CPUID_EDX_RESERVED(CpuidPacket->EDX));

                    //
                    // Display summary
                    //
                    ShowMessages("-- Frequency Summary --\n\n");
                    ShowMessages("  Base Frequency:     ");
                    if (BaseFreq == 0)
                    {
                        ShowMessages("Not Supported\n");
                    }
                    else
                    {
                        ShowMessages("%u MHz\n", BaseFreq);
                    }

                    //
                    // Maximum frequency
                    //
                    ShowMessages("  Maximum Frequency:  ");
                    if (MaxFreq == 0)
                    {
                        ShowMessages("Not Supported\n");
                    }
                    else
                    {
                        ShowMessages("%u MHz\n", MaxFreq);
                    }

                    //
                    // Bus frequency
                    //
                    ShowMessages("  Bus Frequency:      ");
                    if (BusFreq == 0)
                    {
                        ShowMessages("Not Supported\n");
                    }
                    else
                    {
                        ShowMessages("%u MHz\n\n", BusFreq);
                    }

                    //
                    // Show turbo boost if both base and max are supported and max > base
                    //
                    if (BaseFreq > 0 && MaxFreq > 0 && MaxFreq > BaseFreq)
                    {
                        UINT32 TurboBoost   = MaxFreq - BaseFreq;
                        FLOAT  TurboPercent = ((FLOAT)TurboBoost / BaseFreq) * 100.0f;
                        ShowMessages("  Turbo Boost:        %u MHz above base (%.1f%% increase)\n\n",
                                     TurboBoost,
                                     TurboPercent);
                    }

                    ShowMessages("  *******************************************************\n");
                    ShowMessages("  *  NOTE: These values are for display purposes only   *\n");
                    ShowMessages("  *  They do not reflect actual running frequencies     *\n");
                    ShowMessages("  *  Actual frequencies depend on workload, power, etc. *\n");
                    ShowMessages("  *******************************************************\n\n");

                    break;
                }

                case 0x17:
                {
                    ShowMessages("==== CPUID.(EAX=17H) SoC Vendor Information ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *             Max NumberOfSubLeaves = %u               *\n"
                                 "  *******************************************************\n\n",
                                 CPUID_EAX_MAX_SOC_ID_INDEX(CpuidPacket->EAX));

                    ShowMessages("==== CPUID.(EAX=17H, ECX=%u) SoC Vendor Information ====\n\n", SubFunctionId);

                    if (SubFunctionId == 0)
                    {
                        //
                        // Main
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  MaxSocIdIndex = %u\n\n", CPUID_EAX_MAX_SOC_ID_INDEX(CpuidPacket->EAX));

                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  SocVendorId = 0x%04X\n",
                                     CPUID_EBX_SOC_VENDOR_ID(CpuidPacket->EBX));
                        ShowMessages("  IsVendorScheme = %s\n\n",
                                     CPUID_EBX_IS_VENDOR_SCHEME(CpuidPacket->EBX) ? "TRUE (Industry Standard)" : "FALSE (Intel Assigned)");

                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  ProjectId = 0x%08X\n\n",
                                     CPUID_ECX_PROJECT_ID(CpuidPacket->ECX));

                        ShowMessages("-- EDX --\n\n");
                        ShowMessages("  SteppingId = 0x%08X\n\n",
                                     CPUID_EDX_STEPPING_ID(CpuidPacket->EDX));
                    }

                    else if (SubFunctionId >= 1 && SubFunctionId <= 3)
                    {
                        //
                        // subleaves 1-3 (brand string)
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  SocVendorBrandString[0..3] = 0x%08X (%c%c%c%c)\n\n",
                                     CPUID_EAX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EAX),
                                     (CPUID_EAX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EAX) >> 0) & 0xFF,
                                     (CPUID_EAX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EAX) >> 8) & 0xFF,
                                     (CPUID_EAX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EAX) >> 16) & 0xFF,
                                     (CPUID_EAX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EAX) >> 24) & 0xFF);

                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  SocVendorBrandString[4..7] = 0x%08X (%c%c%c%c)\n\n",
                                     CPUID_EBX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EBX),
                                     (CPUID_EBX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EBX) >> 0) & 0xFF,
                                     (CPUID_EBX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EBX) >> 8) & 0xFF,
                                     (CPUID_EBX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EBX) >> 16) & 0xFF,
                                     (CPUID_EBX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EBX) >> 24) & 0xFF);

                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  SocVendorBrandString[8..11] = 0x%08X (%c%c%c%c)\n\n",
                                     CPUID_ECX_SOC_VENDOR_BRAND_STRING(CpuidPacket->ECX),
                                     (CPUID_ECX_SOC_VENDOR_BRAND_STRING(CpuidPacket->ECX) >> 0) & 0xFF,
                                     (CPUID_ECX_SOC_VENDOR_BRAND_STRING(CpuidPacket->ECX) >> 8) & 0xFF,
                                     (CPUID_ECX_SOC_VENDOR_BRAND_STRING(CpuidPacket->ECX) >> 16) & 0xFF,
                                     (CPUID_ECX_SOC_VENDOR_BRAND_STRING(CpuidPacket->ECX) >> 24) & 0xFF);

                        ShowMessages("-- EDX --\n\n");
                        ShowMessages("  SocVendorBrandString[12..15] = 0x%08X (%c%c%c%c)\n\n",
                                     CPUID_EDX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EDX),
                                     (CPUID_EDX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EDX) >> 0) & 0xFF,
                                     (CPUID_EDX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EDX) >> 8) & 0xFF,
                                     (CPUID_EDX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EDX) >> 16) & 0xFF,
                                     (CPUID_EDX_SOC_VENDOR_BRAND_STRING(CpuidPacket->EDX) >> 24) & 0xFF);
                    }

                    else
                    {
                        //
                        // Sub-leaves > MaxSOCID_Index (Reserved, should return all zeros)
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EAX_RESERVED(CpuidPacket->EAX));

                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EBX_RESERVED(CpuidPacket->EBX));

                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n", CPUID_ECX_RESERVED(CpuidPacket->ECX));

                        ShowMessages("-- EDX --\n\n");
                        ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EDX_RESERVED(CpuidPacket->EDX));
                    }
                    break;
                }

                case 0x18:
                    //
                    // DAT, 0x18 = 24 (decimal)
                    //
                    ShowMessages("==== CPUID.(EAX=18H) Deterministic Address Translation Parameters ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *             Max NumberOfSubLeaves = %u               *\n"
                                 "  *******************************************************\n\n",
                                 CpuidPacket->LeafEaxMaxSubleaf);

                    ShowMessages("==== CPUID.(EAX=18H, ECX=%u) Deterministic Address Translation Parameters ====\n\n", SubFunctionId);

                    if (SubFunctionId == 0)
                    {
                        //
                        // main
                        //
                        ShowMessages("-- EAX --\n\n");
                        ShowMessages("  MaxSubLeaf = %u\n\n", CPUID_EAX_MAX_SUB_LEAF(CpuidPacket->EAX));

                        //
                        // EBX: Page size support and associativity
                        //
                        ShowMessages("-- EBX --\n\n");
                        ShowMessages("  PageEntries4KbSupported    = %s\n",
                                     CPUID_EBX_PAGE_ENTRIES_4KB_SUPPORTED(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  PageEntries2MbSupported    = %s\n",
                                     CPUID_EBX_PAGE_ENTRIES_2MB_SUPPORTED(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  PageEntries4MbSupported    = %s\n",
                                     CPUID_EBX_PAGE_ENTRIES_4MB_SUPPORTED(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  PageEntries1GbSupported    = %s\n",
                                     CPUID_EBX_PAGE_ENTRIES_1GB_SUPPORTED(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                        ShowMessages("  Partitioning               = %u%s\n",
                                     CPUID_EBX_PARTITIONING(CpuidPacket->EBX),
                                     CPUID_EBX_PARTITIONING(CpuidPacket->EBX) == 0 ? " (soft partitioning)" : "");
                        ShowMessages("  WaysOfAssociativity (W)    = %u\n\n",
                                     CPUID_EBX_WAYS_OF_ASSOCIATIVITY_00(CpuidPacket->EBX));

                        //
                        // ECX: Number of Sets
                        //
                        ShowMessages("-- ECX --\n\n");
                        ShowMessages("  NumberOfSets               = %u\n\n",
                                     CPUID_ECX_NUMBER_OF_SETS(CpuidPacket->ECX));

                        //
                        // EDX: Translation cache type and properties
                        //
                        ShowMessages("-- EDX --\n\n");

                        switch (CPUID_EDX_TRANSLATION_CACHE_TYPE_FIELD(CpuidPacket->EDX))
                        {
                        case 0:
                            TypeName = "Null (sub-leaf not valid)";
                            break;
                        case 1:
                            TypeName = "Data TLB";
                            break;
                        case 2:
                            TypeName = "Instruction TLB";
                            break;
                        case 3:
                            TypeName = "Unified TLB";
                            break;
                        default:
                            TypeName = "Reserved";
                            break;
                        }
                        ShowMessages("  TranslationCacheTypeField  = %u (%s)\n",
                                     CPUID_EDX_TRANSLATION_CACHE_TYPE_FIELD(CpuidPacket->EDX),
                                     TypeName);
                        ShowMessages("  TranslationCacheLevel      = %u\n",
                                     CPUID_EDX_TRANSLATION_CACHE_LEVEL(CpuidPacket->EDX));
                        ShowMessages("  FullyAssociativeStructure  = %s%s\n",
                                     CPUID_EDX_FULLY_ASSOCIATIVE_STRUCTURE(CpuidPacket->EDX) ? "TRUE" : "FALSE",
                                     CPUID_EDX_FULLY_ASSOCIATIVE_STRUCTURE(CpuidPacket->EDX) ? " (fully associative)" : "");

                        ShowMessages("  MaxAddressableIdsForLogicalProcessors (raw) = %u -> actual = %u (raw + 1)\n",
                                     CPUID_EDX_MAX_ADDRESSABLE_IDS_FOR_LOGICAL_PROCESSORS(CpuidPacket->EDX),
                                     CPUID_EDX_MAX_ADDRESSABLE_IDS_FOR_LOGICAL_PROCESSORS(CpuidPacket->EDX) + 1);
                    }

                    else
                    {
                        //
                        // subleaves >= 1 (Translation Structure Information)
                        //

                        //
                        // Check if this sub-leaf is valid (EDX[4:0] != 0)
                        //
                        if (CPUID_EDX_TRANSLATION_CACHE_TYPE_FIELD(CpuidPacket->EDX) == 0)
                        {
                            ShowMessages("  Sub-leaf %u is invalid (TranslationCacheTypeField = 0)\n", SubFunctionId);
                            ShowMessages("  All registers should be zero according to spec:\n");
                            ShowMessages("  EAX = 0x%08X\n", CPUID_EAX_RESERVED(CpuidPacket->EAX));
                            ShowMessages("  EBX = 0x%08X\n", CpuidPacket->EBX);
                            ShowMessages("  ECX = 0x%08X\n", CpuidPacket->ECX);
                            ShowMessages("  EDX = 0x%08X\n", CpuidPacket->EDX);
                        }

                        else
                        {
                            //
                            // EAX: Reserved for sub-leaves >= 1
                            //
                            ShowMessages("-- EAX --\n\n");
                            ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EAX_RESERVED(CpuidPacket->EAX));

                            //
                            // EBX: Page size support and associativity
                            //
                            ShowMessages("-- EBX --\n\n");
                            ShowMessages("  PageEntries4KbSupported    = %s\n",
                                         CPUID_EBX_PAGE_ENTRIES_4KB_SUPPORTED(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                            ShowMessages("  PageEntries2MbSupported    = %s\n",
                                         CPUID_EBX_PAGE_ENTRIES_2MB_SUPPORTED(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                            ShowMessages("  PageEntries4MbSupported    = %s\n",
                                         CPUID_EBX_PAGE_ENTRIES_4MB_SUPPORTED(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                            ShowMessages("  PageEntries1GbSupported    = %s\n",
                                         CPUID_EBX_PAGE_ENTRIES_1GB_SUPPORTED(CpuidPacket->EBX) ? "TRUE" : "FALSE");
                            ShowMessages("  Partitioning               = %u%s\n",
                                         CPUID_EBX_PARTITIONING(CpuidPacket->EBX),
                                         CPUID_EBX_PARTITIONING(CpuidPacket->EBX) == 0 ? " (soft partitioning)" : "");
                            ShowMessages("  WaysOfAssociativity (W)    = %u\n\n",
                                         CPUID_EBX_WAYS_OF_ASSOCIATIVITY_01(CpuidPacket->EBX));

                            // ECX: Number of Sets
                            ShowMessages("-- ECX --\n\n");
                            ShowMessages("  NumberOfSets               = %u\n\n",
                                         CPUID_ECX_NUMBER_OF_SETS(CpuidPacket->ECX));

                            // EDX: Translation cache type and properties
                            ShowMessages("-- EDX --\n\n");
                            switch (CPUID_EDX_TRANSLATION_CACHE_TYPE_FIELD(CpuidPacket->EDX))
                            {
                            case 0:
                                TypeName = "Null (sub-leaf not valid)";
                                break;
                            case 1:
                                TypeName = "Data TLB";
                                break;
                            case 2:
                                TypeName = "Instruction TLB";
                                break;
                            case 3:
                                TypeName = "Unified TLB";
                                break;
                            default:
                                TypeName = "Reserved";
                                break;
                            }
                            ShowMessages("  TranslationCacheTypeField  = %u (%s)\n",
                                         CPUID_EDX_TRANSLATION_CACHE_TYPE_FIELD(CpuidPacket->EDX),
                                         TypeName);
                            ShowMessages("  TranslationCacheLevel      = %u\n",
                                         CPUID_EDX_TRANSLATION_CACHE_LEVEL(CpuidPacket->EDX));
                            ShowMessages("  FullyAssociativeStructure  = %s%s\n",
                                         CPUID_EDX_FULLY_ASSOCIATIVE_STRUCTURE(CpuidPacket->EDX) ? "TRUE" : "FALSE",
                                         CPUID_EDX_FULLY_ASSOCIATIVE_STRUCTURE(CpuidPacket->EDX) ? " (fully associative)" : "");

                            ShowMessages("  MaxAddressableIdsForLogicalProcessors (raw) = %u -> actual = %u (raw + 1)\n",
                                         CPUID_EDX_MAX_ADDRESSABLE_IDS_FOR_LOGICAL_PROCESSORS(CpuidPacket->EDX),
                                         CPUID_EDX_MAX_ADDRESSABLE_IDS_FOR_LOGICAL_PROCESSORS(CpuidPacket->EDX) + 1);
                        }
                    }

                    break;

                case 0x80000000:
                    ShowMessages("==== CPUID.(EAX=80000000H) Extended Function Information ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *           LEAF 0x80000000 HAS NO SUBLEAVES          *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    ShowMessages("-- EAX --\n\n");
                    ShowMessages("  MaxExtendedFunctions = 0x%08X (%u)\n\n",
                                 CPUID_EAX_MAX_EXTENDED_FUNCTIONS(CpuidPacket->EAX),
                                 CPUID_EAX_MAX_EXTENDED_FUNCTIONS(CpuidPacket->EAX));

                    ShowMessages("-- EBX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EBX_RESERVED(CpuidPacket->EBX));

                    ShowMessages("-- ECX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_ECX_RESERVED(CpuidPacket->ECX));

                    ShowMessages("-- EDX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EDX_RESERVED(CpuidPacket->EDX));

                    break;

                case 0x80000001:
                    ShowMessages("==== CPUID.(EAX=80000001H) Extended CPU Signature ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *           LEAF 0x80000001 HAS NO SUBLEAVES          *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    ShowMessages("-- EAX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EAX_RESERVED(CpuidPacket->EAX));

                    ShowMessages("-- EBX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EBX_RESERVED(CpuidPacket->EBX));

                    ShowMessages("-- ECX --\n\n");
                    ShowMessages("  LAHF/SAHF Available in 64-bit Mode = %s\n",
                                 CPUID_ECX_LAHF_SAHF_AVAILABLE_IN_64_BIT_MODE(CpuidPacket->ECX) ? "True" : "False");
                    ShowMessages("  LZCNT                              = %s\n",
                                 CPUID_ECX_LZCNT(CpuidPacket->ECX) ? "True" : "False");
                    ShowMessages("  PREFETCHW                          = %s\n\n",
                                 CPUID_ECX_PREFETCHW(CpuidPacket->ECX) ? "True" : "False");

                    ShowMessages("-- EDX --\n\n");
                    ShowMessages("  SYSCALL/SYSRET Available in 64-bit Mode = %s\n",
                                 CPUID_EDX_SYSCALL_SYSRET_AVAILABLE_IN_64_BIT_MODE(CpuidPacket->EDX) ? "True" : "False");
                    ShowMessages("  Execute Disable Bit Available            = %s\n",
                                 CPUID_EDX_EXECUTE_DISABLE_BIT_AVAILABLE(CpuidPacket->EDX) ? "True" : "False");
                    ShowMessages("  1-GByte Pages Available                 = %s\n",
                                 CPUID_EDX_PAGES_1GB_AVAILABLE(CpuidPacket->EDX) ? "True" : "False");
                    ShowMessages("  RDTSCP Available                        = %s\n",
                                 CPUID_EDX_RDTSCP_AVAILABLE(CpuidPacket->EDX) ? "True" : "False");
                    ShowMessages("  Intel 64 Architecture Available         = %s\n\n",
                                 CPUID_EDX_IA64_AVAILABLE(CpuidPacket->EDX) ? "True" : "False");

                    break;
                //
                // 0x80000002-0x80000004 - Processor brand string
                //
                case 0x80000002:
                case 0x80000003:
                case 0x80000004:
                {
                    ShowMessages("==== CPUID.(EAX=80000002H-80000004H) Processor Information ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *         LEAF 0x80000002-4 HAS NO SUBLEAVES          *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");
                    ShowMessages("  Brand String = \"%s\"\n\n", CpuidPacket->BrandString);

                    break;
                }
                case 0x80000005:
                    ShowMessages("EAX = 0x80000005: not implemented.\n");
                    break;

                case 0x80000006:
                {
                    ShowMessages("==== CPUID.(EAX=80000006H) Extended Cache Information ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *          LEAF 0x80000006 HAS NO SUBLEAVES           *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    ShowMessages("-- EAX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EAX_RESERVED(CpuidPacket->EAX));

                    ShowMessages("-- EBX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EBX_RESERVED(CpuidPacket->EBX));

                    ShowMessages("-- ECX (L2 Cache Information) --\n");

                    UINT32 LineSize  = CPUID_ECX_CACHE_LINE_SIZE_IN_BYTES(CpuidPacket->ECX);
                    UINT32 Assoc     = CPUID_ECX_L2_ASSOCIATIVITY_FIELD(CpuidPacket->ECX);
                    UINT32 CacheSize = CPUID_ECX_CACHE_SIZE_IN_1K_UNITS(CpuidPacket->ECX);

                    //
                    // decode associativity
                    //
                    switch (Assoc)
                    {
                    case 0x00:
                        AssocName = "Disabled";
                        break;
                    case 0x01:
                        AssocName = "Direct mapped";
                        break;
                    case 0x02:
                        AssocName = "2-way";
                        break;
                    case 0x04:
                        AssocName = "4-way";
                        break;
                    case 0x06:
                        AssocName = "8-way";
                        break;
                    case 0x08:
                        AssocName = "16-way";
                        break;
                    case 0x0F:
                        AssocName = "Fully associative";
                        break;
                    default:
                        AssocName = "Reserved";
                        break;
                    }
                    ShowMessages("  CacheLineSizeInBytes       = %u bytes\n", LineSize);
                    ShowMessages("  L2AssociativityField       = 0x%02X (%s)\n", Assoc, AssocName);
                    ShowMessages("  CacheSizeIn1KUnits         = %u KB (%u MB)\n",
                                 CacheSize,
                                 CacheSize / 1024);

                    ShowMessages("-- EDX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EDX_RESERVED(CpuidPacket->EDX));

                    break;
                }

                case 0x80000007:
                    ShowMessages("==== CPUID.(EAX=80000007H) Extended Time Stamp Counter ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *          LEAF 0x80000007 HAS NO SUBLEAVES           *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    ShowMessages("-- EAX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EAX_RESERVED(CpuidPacket->EAX));

                    ShowMessages("-- EBX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EBX_RESERVED(CpuidPacket->EBX));

                    ShowMessages("-- ECX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_ECX_RESERVED(CpuidPacket->ECX));

                    ShowMessages("-- EDX --\n\n");
                    ShowMessages("  InvariantTscAvailable = %u%s\n\n",
                                 CPUID_EDX_INVARIANT_TSC_AVAILABLE(CpuidPacket->EDX),
                                 CPUID_EDX_INVARIANT_TSC_AVAILABLE(CpuidPacket->EDX) ? " (TSC runs at constant rate)" : "");

                    break;

                case 0x80000008:
                {
                    ShowMessages("==== CPUID.(EAX=80000008H) Virtual & Physical Address Sizes ====\n\n");
                    ShowMessages("  *******************************************************\n"
                                 "  *          LEAF 0x80000008 HAS NO SUBLEAVES           *\n"
                                 "  *       ANY SUBLEAF YOU ENTER WILL DEFAULT TO 0       *\n"
                                 "  *      AND THE PROCESSOR RETURNS UNDEFINED VALUES     *\n"
                                 "  *******************************************************\n\n");

                    ShowMessages("-- EAX --\n\n");
                    UINT32 PhysicalBits = CPUID_EAX_NUMBER_OF_PHYSICAL_ADDRESS_BITS(CpuidPacket->EAX);
                    UINT32 LinearBits   = CPUID_EAX_NUMBER_OF_LINEAR_ADDRESS_BITS(CpuidPacket->EAX);

                    ShowMessages("  NumberOfPhysicalAddressBits = %u (max physical address = 2^%u = %llu bytes)\n",
                                 PhysicalBits,
                                 PhysicalBits,
                                 (ULONG64)(1ULL << PhysicalBits));
                    ShowMessages("  NumberOfLinearAddressBits  = %u (max linear address = 2^%u = %llu bytes)\n",
                                 LinearBits,
                                 LinearBits,
                                 (ULONG64)(1ULL << LinearBits));

                    ShowMessages("-- EBX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EBX_RESERVED(CpuidPacket->EBX));

                    ShowMessages("-- ECX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_ECX_RESERVED(CpuidPacket->ECX));

                    ShowMessages("-- EDX --\n\n");
                    ShowMessages("  Reserved = 0x%08X\n\n", CPUID_EDX_RESERVED(CpuidPacket->EDX));

                    break;
                }

                default:
                    ShowMessages("==== CPUID.(EAX=%08XH) ====\n\n", FunctionId);
                    ShowMessages("  CPUID leaf 0x%08X is not implemented in HyperDbg.\n", FunctionId);
                    ShowMessages("  You can decode the raw values yourself:\n");
                    ShowMessages("    EAX: 0x%08X\n", CpuidPacket->EAX);
                    ShowMessages("    EBX: 0x%08X\n", CpuidPacket->EBX);
                    ShowMessages("    ECX: 0x%08X\n", CpuidPacket->ECX);
                    ShowMessages("    EDX: 0x%08X\n\n", CpuidPacket->EDX);
                }
            }
            else
            {
                ShowErrorMessage(CpuidPacket->KernelStatus);
            }

            //
            // Signal the event relating to receiving result of CPUID
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_USER_CPUID_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_CALLSTACK:

            CallstackPacket      = (DEBUGGER_CALLSTACK_REQUEST *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));
            CallstackFramePacket = (DEBUGGER_SINGLE_CALLSTACK_FRAME *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET) + sizeof(DEBUGGER_CALLSTACK_REQUEST));

            if (CallstackPacket->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                //
                // Show the callstack
                //
                CallstackShowFrames(CallstackFramePacket,
                                    CallstackPacket->FrameCount,
                                    CallstackPacket->DisplayMethod,
                                    CallstackPacket->Is32Bit);
            }
            else
            {
                ShowErrorMessage(CallstackPacket->KernelStatus);
            }

            //
            // Signal the event relating to receiving result of callstack
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_CALLSTACK_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_TEST_QUERY:

            TestQueryPacket = (DEBUGGER_DEBUGGER_TEST_QUERY_BUFFER *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (TestQueryPacket->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                switch (TestQueryPacket->RequestType)
                {
                case TEST_BREAKPOINT_TURN_OFF_BPS:

                    ShowMessages("breakpoint interception (#BP) is deactivated\n"
                                 "from now, the breakpoints will be re-injected into the guest debuggee\n");

                    break;

                case TEST_BREAKPOINT_TURN_ON_BPS:

                    ShowMessages("breakpoint interception (#BP) is activated\n");

                    break;

                case TEST_BREAKPOINT_TURN_OFF_DBS:

                    ShowMessages("debug break interception (#DB) is deactivated\n"
                                 "from now, the debug breaks will be re-injected into the guest debuggee\n");

                    break;

                case TEST_BREAKPOINT_TURN_ON_DBS:

                    ShowMessages("debug break interception (#DB) is activated\n");

                    break;

                default:
                    break;
                }
            }
            else
            {
                ShowErrorMessage(TestQueryPacket->KernelStatus);
            }

            //
            // Signal the event relating to receiving result of test query
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_TEST_QUERY);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_RUNNING_SCRIPT:

            ScriptPacket = (DEBUGGEE_SCRIPT_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (ScriptPacket->Result == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                //
                // Nothing to do
                //
            }
            else
            {
                ShowErrorMessage(ScriptPacket->Result);
            }

            if (ScriptPacket->IsFormat)
            {
                //
                // Signal the event relating to receiving result of the '.formats' command
                //
                DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_SCRIPT_FORMATS_RESULT);
            }

            //
            // Signal the event relating to receiving result of running script
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_SCRIPT_RUNNING_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_FORMATS:

            FormatsPacket = (DEBUGGEE_FORMATS_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // We'll just save the result of expression to the global variables
            // and let the debuggee to decide whether wants to show error or not
            // and let the debuggee to decide whether wants to show error or not
            //
            g_ErrorStateOfResultOfEvaluatedExpression = FormatsPacket->Result;
            g_ResultOfEvaluatedExpression             = FormatsPacket->Value;

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_REGISTERING_EVENT:

            EventAndActionPacket = (DEBUGGER_EVENT_AND_ACTION_RESULT *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Move the buffer to the global variable
            //
            memcpy(&g_DebuggeeResultOfRegisteringEvent, EventAndActionPacket, sizeof(DEBUGGER_EVENT_AND_ACTION_RESULT));

            //
            // Signal the event relating to receiving result of register event
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_REGISTER_EVENT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_ADDING_ACTION_TO_EVENT:

            EventAndActionPacket = (DEBUGGER_EVENT_AND_ACTION_RESULT *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Move the buffer to the global variable
            //
            memcpy(&g_DebuggeeResultOfAddingActionsToEvent, EventAndActionPacket, sizeof(DEBUGGER_EVENT_AND_ACTION_RESULT));

            //
            // Signal the event relating to receiving result of adding action to event
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_ADD_ACTION_TO_EVENT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_QUERY_AND_MODIFY_EVENT:

            EventModifyAndQueryPacket = (DEBUGGER_MODIFY_EVENTS *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Set the result of query
            //
            if (EventModifyAndQueryPacket->KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                //
                // There was an error
                //
                ShowErrorMessage((UINT32)EventModifyAndQueryPacket->KernelStatus);
            }
            else if (EventModifyAndQueryPacket->TypeOfAction == DEBUGGER_MODIFY_EVENTS_QUERY_STATE)
            {
                //
                // Set the global state
                //
                g_SharedEventStatus = EventModifyAndQueryPacket->IsEnabled;
            }
            else
            {
                CommandEventsHandleModifiedEvent(EventModifyAndQueryPacket->Tag,
                                                 EventModifyAndQueryPacket);
            }

            //
            // Signal the event relating to receiving result of event query and
            // modification
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_MODIFY_AND_QUERY_EVENT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RELOAD_SYMBOL_FINISHED:

            SymbolReloadFinishedPacket = (DEBUGGEE_SYMBOL_UPDATE_RESULT *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Show messages as the result of updating symbols
            //
            if (SymbolReloadFinishedPacket->KernelStatus != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                //
                // There was an error
                //
                ShowErrorMessage((UINT32)SymbolReloadFinishedPacket->KernelStatus);
            }
            else
            {
                //
                // Load the symbols
                //
                SymbolInitialReload();
            }

            //
            // Signal the event relating to receiving result of symbol reload
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_SYMBOL_RELOAD);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_READING_REGISTERS:

            ReadRegisterPacket = (DEBUGGEE_REGISTER_READ_DESCRIPTION *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Get the address and size of the caller
            //
            DbgWaitGetKernelRequestData(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_READ_REGISTERS, &CallerAddress, &CallerSize);

            //
            // Copy the memory buffer for the caller
            //
            memcpy(CallerAddress, ReadRegisterPacket, CallerSize);

            //
            // Signal the event relating to receiving result of reading registers
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_READ_REGISTERS);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_WRITE_REGISTER:

            WriteRegisterPacket = (DEBUGGEE_REGISTER_WRITE_DESCRIPTION *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Get the address and size of the caller
            //
            DbgWaitGetKernelRequestData(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_WRITE_REGISTER, &CallerAddress, &CallerSize);

            //
            // Copy the memory buffer for the caller
            //
            memcpy(CallerAddress, WriteRegisterPacket, CallerSize);

            //
            // Signal the event relating to receiving result of writing register
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_WRITE_REGISTER);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_APIC_REQUESTS:

            ApicRequestPacket = (DEBUGGER_APIC_REQUEST *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Get the address and size of the caller
            //
            DbgWaitGetKernelRequestData(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_APIC_ACTIONS, &CallerAddress, &CallerSize);

            //
            // Copy the memory buffer for the caller
            //
            memcpy(CallerAddress, ApicRequestPacket, CallerSize);

            //
            // Signal the event relating to receiving result of performing actions into APIC
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_APIC_ACTIONS);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_QUERY_IDT_ENTRIES_REQUESTS:

            IdtEntryRequestPacket = (INTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Get the address and size of the caller
            //
            DbgWaitGetKernelRequestData(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_IDT_ENTRIES, &CallerAddress, &CallerSize);

            //
            // Copy the memory buffer for the caller
            //
            memcpy(CallerAddress, IdtEntryRequestPacket, CallerSize);

            //
            // Signal the event relating to receiving result of querying IDT entries
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_IDT_ENTRIES);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_READING_MEMORY:

            ReadMemoryPacket = (DEBUGGER_READ_MEMORY *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Get the address and size of the caller
            //
            DbgWaitGetKernelRequestData(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_READ_MEMORY, &CallerAddress, &CallerSize);

            //
            // Copy the memory buffer for the caller
            //
            memcpy(CallerAddress, ReadMemoryPacket, CallerSize);

            //
            // Signal the event relating to receiving result of reading memory
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_READ_MEMORY);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_EDITING_MEMORY:

            EditMemoryPacket = (DEBUGGER_EDIT_MEMORY *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Get the address and size of the caller
            //
            DbgWaitGetKernelRequestData(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_EDIT_MEMORY, &CallerAddress, &CallerSize);

            //
            // Copy the memory buffer for the caller
            //
            memcpy(CallerAddress, EditMemoryPacket, CallerSize);

            //
            // Signal the event relating to receiving result of editing memory
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_EDIT_MEMORY);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_BP:

            BpPacket = (DEBUGGEE_BP_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (BpPacket->Result == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                //
                // Everything was okay, nothing to do
                //
            }
            else
            {
                ShowErrorMessage(BpPacket->Result);
            }

            //
            // Signal the event relating to receiving result of putting breakpoints
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_BP);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_SHORT_CIRCUITING_STATE:

            ShortCircuitingPacket = (DEBUGGER_SHORT_CIRCUITING_EVENT *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (ShortCircuitingPacket->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                ShowMessages("the event's short-circuiting state changed to %s\n", ShortCircuitingPacket->IsShortCircuiting ? "'on'" : "'off'");
            }
            else
            {
                ShowErrorMessage((UINT32)ShortCircuitingPacket->KernelStatus);
            }

            //
            // Signal the event relating to receiving result of changing the short circuiting state
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_SHORT_CIRCUITING_EVENT_STATE);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_PTE:

            PtePacket = (DEBUGGER_READ_PAGE_TABLE_ENTRIES_DETAILS *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (PtePacket->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                //
                // Show the Page Tables result
                //
                CommandPteShowResults(PtePacket->VirtualAddress, PtePacket);
            }
            else
            {
                ShowErrorMessage(PtePacket->KernelStatus);
            }

            //
            // Signal the event relating to receiving result of PTE query
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_PTE_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_SMI_OPERATION_REQUESTS:

            SmiOperationPacket = (SMI_OPERATION_PACKETS *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Get the address and size of the caller
            //
            DbgWaitGetKernelRequestData(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_SMI_OPERATION_RESULT, &CallerAddress, &CallerSize);

            //
            // Copy the memory buffer for the caller
            //
            memcpy(CallerAddress, SmiOperationPacket, CallerSize);

            //
            // Signal the event relating to receiving result of SMI operation
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_SMI_OPERATION_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_HYPERTRACE_LBR_DUMP_REQUESTS:

            HyperTraceLbrdumpPacket = (HYPERTRACE_LBR_DUMP_PACKETS *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Get the address and size of the caller
            //
            DbgWaitGetKernelRequestData(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_HYPERTRACE_LBR_DUMP_RESULT, &CallerAddress, &CallerSize);

            //
            // Copy the memory buffer for the caller
            //
            memcpy(CallerAddress, HyperTraceLbrdumpPacket, CallerSize);

            //
            // Signal the event relating to receiving result of HyperTrace LBR dump
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_HYPERTRACE_LBR_DUMP_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_HYPERTRACE_PT_OPERATION_REQUESTS:

            HyperTracePtOperationPacket = (HYPERTRACE_PT_OPERATION_PACKETS *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            //
            // Get the address and size of the caller
            //
            DbgWaitGetKernelRequestData(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_HYPERTRACE_PT_OPERATION_RESULT, &CallerAddress, &CallerSize);

            //
            // Copy the memory buffer for the caller
            //
            memcpy(CallerAddress, HyperTracePtOperationPacket, CallerSize);

            //
            // Signal the event relating to receiving result of HyperTrace PT operation
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_HYPERTRACE_PT_OPERATION_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_BRINGING_PAGES_IN:

            PageinPacket = (DEBUGGER_PAGE_IN_REQUEST *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (PageinPacket->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                //
                // Show the successful delivery of the packet
                //
                ShowMessages("the page-fault is delivered to the target thread\n"
                             "press 'g' to continue debuggee (the current thread will execute ONLY one instruction and will be halted again)...\n");
            }
            else
            {
                ShowErrorMessage(PageinPacket->KernelStatus);
            }

            //
            // Signal the event relating to receiving result of page-in request
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_PAGE_IN_STATE);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_VA2PA_AND_PA2VA:

            Va2paPa2vaPacket = (DEBUGGER_VA2PA_AND_PA2VA_COMMANDS *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (Va2paPa2vaPacket->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                if (Va2paPa2vaPacket->IsVirtual2Physical)
                {
                    ShowMessages("%llx\n", Va2paPa2vaPacket->PhysicalAddress);
                }
                else
                {
                    ShowMessages("%llx\n", Va2paPa2vaPacket->VirtualAddress);
                }
            }
            else
            {
                ShowErrorMessage(Va2paPa2vaPacket->KernelStatus);
            }

            //
            // Signal the event relating to receiving result of VA2PA or PA2VA queries
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_VA2PA_AND_PA2VA_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_LIST_OR_MODIFY_BREAKPOINTS:

            ListOrModifyBreakpointPacket = (DEBUGGEE_BP_LIST_OR_MODIFY_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (ListOrModifyBreakpointPacket->Result == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                //
                // Everything was okay, nothing to do
                //
            }
            else
            {
                ShowErrorMessage(ListOrModifyBreakpointPacket->Result);
            }

            //
            // Signal the event relating to receiving result of modifying or listing
            // breakpoints
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_LIST_OR_MODIFY_BREAKPOINTS);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_UPDATE_SYMBOL_INFO:

            SymbolUpdatePacket = (DEBUGGER_UPDATE_SYMBOL_TABLE *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));
            //
            // Perform updates for the symbol table
            //
            SymbolBuildAndUpdateSymbolTable(&SymbolUpdatePacket->SymbolDetailPacket);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_PCITREE:

            PcitreePacket = (DEBUGGEE_PCITREE_REQUEST_RESPONSE_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (PcitreePacket->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                //
                // Print PCI device tree
                //
                ShowMessages("%-12s | %-9s | %-17s | %s \n%s\n", "DBDF", "VID:DID", "Vendor Name", "Device Name", "----------------------------------------------------------------------");
                for (UINT8 i = 0; i < (PcitreePacket->DeviceInfoListNum < DEV_MAX_NUM ? PcitreePacket->DeviceInfoListNum : DEV_MAX_NUM); i++)
                {
                    Vendor * CurrentVendor     = GetVendorById(PcitreePacket->DeviceInfoList[i].ConfigSpace.VendorId);
                    char *   CurrentVendorName = (char *)"N/A";
                    char *   CurrentDeviceName = (char *)"N/A";

                    if (CurrentVendor != NULL)
                    {
                        CurrentVendorName      = CurrentVendor->VendorName;
                        Device * CurrentDevice = GetDeviceFromVendor(CurrentVendor, PcitreePacket->DeviceInfoList[i].ConfigSpace.DeviceId);

                        if (CurrentDevice != NULL)
                        {
                            CurrentDeviceName = CurrentDevice->DeviceName;
                        }
                    }

                    ShowMessages("%04x:%02x:%02x:%x | %04x:%04x | %-17.*s | %.*s\n",
                                 0, // TODO: Add support for domains beyond 0000
                                 PcitreePacket->DeviceInfoList[i].Bus,
                                 PcitreePacket->DeviceInfoList[i].Device,
                                 PcitreePacket->DeviceInfoList[i].Function,
                                 PcitreePacket->DeviceInfoList[i].ConfigSpace.VendorId,
                                 PcitreePacket->DeviceInfoList[i].ConfigSpace.DeviceId,
                                 PlatformStrnlen(CurrentVendorName, PCI_NAME_STR_LENGTH),
                                 CurrentVendorName,
                                 PlatformStrnlen(CurrentDeviceName, PCI_NAME_STR_LENGTH),
                                 CurrentDeviceName

                    );

                    FreeVendor(CurrentVendor);
                }
                FreePciIdDatabase();
            }
            else
            {
                ShowErrorMessage(PcitreePacket->KernelStatus);
            }

            //
            // Signal the event relating to receiving result of pcitree query
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_PCITREE_RESULT);

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_DEBUGGEE_RESULT_OF_PCIDEVINFO:

            PcidevinfoPacket = (DEBUGGEE_PCIDEVINFO_REQUEST_RESPONSE_PACKET *)(((CHAR *)TheActualPacket) + sizeof(DEBUGGER_REMOTE_PACKET));

            if (PcidevinfoPacket->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
            {
                // For some reason, MSVC refuses to initialize these at top of case
                const CHAR * PciHeaderTypeAsString[]  = {"Endpoint", "PCI-to-PCI Bridge", "PCI-to-CardBus Bridge"};
                const CHAR * PciMmioBarTypeAsString[] = {"32-bit Wide",
                                                         "Reserved",
                                                         "64-bit Wide",
                                                         "Reserved"};
                UINT8        BarNumOffset             = 0;

                ShowMessages("PCI configuration space (CAM) for device %04x:%02x:%02x:%x\n",
                             0, // TODO: Add support for domains beyond 0000
                             PcidevinfoPacket->DeviceInfo.Bus,
                             PcidevinfoPacket->DeviceInfo.Device,
                             PcidevinfoPacket->DeviceInfo.Function);

                if (!PcidevinfoPacket->PrintRaw)
                {
                    Vendor * CurrentVendor     = GetVendorById(PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.VendorId);
                    CHAR *   CurrentVendorName = (CHAR *)"N/A";
                    CHAR *   CurrentDeviceName = (CHAR *)"N/A";

                    if (CurrentVendor != NULL)
                    {
                        CurrentVendorName      = CurrentVendor->VendorName;
                        Device * CurrentDevice = GetDeviceFromVendor(CurrentVendor, PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.DeviceId);

                        if (CurrentDevice != NULL)
                        {
                            CurrentDeviceName = CurrentDevice->DeviceName;
                        }
                    }

                    ShowMessages("\nCommon Header:\nVID:DID: %04x:%04x\nVendor Name: %-17.*s\nDevice Name: %.*s\nCommand: %04x\n",
                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.VendorId,
                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.DeviceId,
                                 PlatformStrnlen(CurrentVendorName, PCI_NAME_STR_LENGTH),
                                 CurrentVendorName,
                                 PlatformStrnlen(CurrentDeviceName, PCI_NAME_STR_LENGTH),
                                 CurrentDeviceName,
                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.Command);

                    if ((PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType & 0x01) << 7 == 0) // Only applicable to endpoints
                    {
                        ShowMessages("  Memory Space: %u\n  I/O Space: %u\n",
                                     (PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.Command & 0x2) >> 1,
                                     (PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.Command & 0x1));
                    }

                    ShowMessages("Status: %04x\nRevision ID: %02x\nClass Code: %06x\nCacheLineSize: %02x\nPrimaryLatencyTimer: %02x\nHeaderType: %s (%02x)\n  Multi-function Device: %s\nBist: %02x\n",
                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.Status,
                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.RevisionId,
                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.ClassCode,
                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.CacheLineSize,
                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.PrimaryLatencyTimer,
                                 (PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType & 0x3f) < 2 ? PciHeaderTypeAsString[(PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType & 0x1)] : "Unknown",
                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType,
                                 (PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType & 0x1) ? "True" : "False",
                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.Bist);
                    FreeVendor(CurrentVendor);
                    FreePciIdDatabase();

                    ShowMessages("\nDevice Header:\n");

                    if ((PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType & 0x01) << 7 == 0) // Endpoint
                    {
                        for (UINT8 i = 0; i < 5; i++)
                        {
                            // Memory I/O
                            if ((PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i] & 0x1) == 0)
                            {
                                // 64-bit BAR
                                if (((PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i] & 0x6) >> 1) == 2)
                                {
                                    UINT64 BarMsb    = PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i + 1];
                                    UINT64 BarLsb    = PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i];
                                    UINT64 ActualBar = ((BarMsb & 0xFFFFFFFF) << 32) + (BarLsb & 0xFFFFFFF0);

                                    ShowMessages("BAR%u %s\n BAR Type: MMIO\n MMIO BAR Type: %s (%02x)\n BAR MSB: %08x\n BAR LSB: %08x\n BAR (actual): %016llx\n Prefetchable: %s\n",
                                                 i - BarNumOffset,
                                                 ((PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.Command & 0x2) >> 1 == 0) || !PcidevinfoPacket->DeviceInfo.MmioBarInfo[i].IsEnabled ? "[disabled]" : "",
                                                 PciMmioBarTypeAsString[(PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i] & 0x6) >> 1],
                                                 (PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i] & 0x6) >> 1,
                                                 BarMsb,
                                                 BarLsb,
                                                 ActualBar,
                                                 (PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i] & 0x8 >> 3) ? "True" : "False");
                                    i++;
                                    BarNumOffset++;
                                }
                                // 32-bit BAR
                                else
                                {
                                    UINT32 ActualBar = (PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i] & 0xFFFFFFF0);

                                    ShowMessages("BAR%u %s\n BAR Type: MMIO\n BAR: %08x\n BAR (actual): %08x\n Prefetchable: %s\n",
                                                 i - BarNumOffset,
                                                 ((PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.Command & 0x2) >> 1 == 0) || !PcidevinfoPacket->DeviceInfo.MmioBarInfo[i].IsEnabled ? "[disabled]" : "",
                                                 PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i],
                                                 ActualBar,
                                                 (PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i] & 0x8 >> 3) ? "True" : "False");
                                }
                            }
                            // Port I/O
                            else
                            {
                                // 32-bit BAR is the only flavor we have here
                                UINT32 ActualBar32 = PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i] & 0xFFFFFFFC;

                                ShowMessages("BAR%u %s\n BAR Type: Port IO\n BAR: %08x\n BAR (actual): %08x\n Reserved: %u\n",
                                             i - BarNumOffset,
                                             ((PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.Command & 0x1) == 0) ? "[disabled]" : "",
                                             PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i],
                                             ActualBar32,
                                             (PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Bar[i] & 0x2) >> 1);
                            }
                        }

                        ShowMessages("Cardbus CIS Pointer: %08x\nSubsystem Vendor ID: %04x\nSubsystem ID: %04x\nROM BAR: %08x\nCapabilities Pointer: %02x\nReserved (0xD): %06x\nReserved (0xE): %08x\nInterrupt Line: %02x\nInterrupt Pin: %02x\nMin Grant: %02x\nMax latency: %02x\n",
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.CardBusCISPtr,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.SubVendorId,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.SubSystemId,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.ROMBar,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.CapabilitiesPtr,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Reserved,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.Reserved1,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.InterruptLine,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.InterruptPin,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.MinGnt,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpaceEp.MaxLat);
                    }
                    else if ((PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType & 0x3f) == 1) // PCI-to-PCI Bridge
                    {
                        ShowMessages("BAR0: %08x\nBAR1: %08x\n", PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.Bar[0], PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.Bar[1]);

                        ShowMessages("Primary Bus Number: %02x\nSecondary Bus Number: %02x\nSubordinate Bus Number: %02x\nSecondary Latency Timer: %02x\nI/O Base: %02x\nI/O Limit: %02x\nSecondary Status: %04x\nMemory Base: %04x\nMemory Limit: %04x\nPrefetchable Memory Base: %04x\nPrefetchable Memory Limit: %04x\nPrefetchable Base Upper 32 Bits: %08x\nPrefetchable Limit Upper 32 Bits: %08x\nI/O Base Upper 16 Bits: %04x\nI/O Limit Upper 16 Bits: %04x\nCapability Pointer: %02x\nReserved: %06x\nROM BAR: %08x\nInterrupt Line: %02x\nInterrupt Pin: %02x\nBridge Control: %04x\n",
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.PrimaryBusNumber,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.SecondaryBusNumber,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.SubordinateBusNumber,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.SecondaryLatencyTimer,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.IoBase,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.IoLimit,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.SecondaryStatus,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.MemoryBase,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.MemoryLimit,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.PrefetchableMemoryBase,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.PrefetchableMemoryLimit,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.PrefetchableBaseUpper32b,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.PrefetchableLimitUpper32b,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.IoLimitUpper16b,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.IoBaseUpper16b,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.CapabilityPtr,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.Reserved,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.ROMBar,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.InterruptLine,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.InterruptPin,
                                     PcidevinfoPacket->DeviceInfo.ConfigSpace.DeviceHeader.ConfigSpacePtpBridge.BridgeControl);
                    }
                    else if ((PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType & 0x3f) == 2) // PCI-to-CardBus Bridge
                    {
                        ShowMessages("Parsing header type %s (%02x) currently unsupported\n", PciHeaderTypeAsString[PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType & 0x01], PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType & 0x01);
                    }
                    else
                    {
                        ShowMessages("\nDevice Header:\nUnknown header type %02x\n", (PcidevinfoPacket->DeviceInfo.ConfigSpace.CommonHeader.HeaderType & 0x3f));
                    }
                }
                else
                {
                    UINT32 * cs = (UINT32 *)&PcidevinfoPacket->DeviceInfo.ConfigSpace; // Overflows into .ConfigSpaceAdditional - no padding due to pack(0)

                    ShowMessages("    00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n");

                    for (UINT16 i = 0; i < CAM_CONFIG_SPACE_LENGTH; i += 16)
                    {
                        ShowMessages("%02x: ", i);
                        for (UINT8 j = 0; j < 16; j++)
                        {
                            ShowMessages("%02x ", *(((BYTE *)cs) + j));
                        }

                        // Print ASCII representation
                        // Replace non-printable characters with "."
                        for (UINT8 j = 0; j < 16; j++)
                        {
                            CHAR c = (CHAR) * (cs + j);
                            if (c >= 32 && c <= 126)
                            {
                                ShowMessages("%c", c);
                            }
                            else
                            {
                                ShowMessages(".");
                            }
                        }
                        ShowMessages("\n");
                        cs += 4;
                    }
                }
            }
            else
            {
                ShowErrorMessage(PcidevinfoPacket->KernelStatus);
            }

            //
            // Signal the event relating to receiving result of pcitree query
            //
            DbgReceivedKernelResponse(DEBUGGER_SYNCRONIZATION_OBJECT_KERNEL_DEBUGGER_PCIDEVINFO_RESULT);

            break;

        default:
            ShowMessages("err, unknown packet action received from the debugger\n");
            break;
        }
    }
    else
    {
        //
        // It's not a HyperDbg packet, it's probably a GDB packet
        //
        ShowMessages("err, invalid packet received\n");
        // DebugBreak();
    }

    //
    // Wait for debug pause command again
    //
    goto StartAgain;

    return TRUE;
}

/**
 * @brief Check if the remote debugger needs to pause the system
 *
 * @param SerialHandle
 * @return BOOLEAN
 */
BOOLEAN
ListeningSerialPortInDebuggee()
{
StartAgain:

    BOOL Status; /* Status */
    CHAR SerialBuffer[MaxSerialPacketSize] = {
        0}; /* Buffer to send and receive data */
#ifdef _WIN32
    DWORD                   EventMask       = 0;    /* Event mask to trigger */
#endif                                              // _WIN32
    char                    ReadData        = NULL; /* temperory Character */
    DWORD                   NoBytesRead     = 0;    /* Bytes read by ReadFile() */
    UINT32                  Loop            = 0;
    PDEBUGGER_REMOTE_PACKET TheActualPacket = (PDEBUGGER_REMOTE_PACKET)SerialBuffer;

#ifdef _WIN32
    //
    // Setting Receive Mask
    //
    Status = SetCommMask(g_SerialRemoteComPortHandle, EV_RXCHAR);
    if (Status == FALSE)
    {
        // ShowMessages("warning, there is an error in setting CommMask\n");

        //
        // Sometimes, this error happens
        //
        // return FALSE;
    }

    //
    // Setting WaitComm() Event
    //
    Status = WaitCommEvent(g_SerialRemoteComPortHandle, &EventMask, NULL); /* Wait for the character to be received */

    if (Status == FALSE)
    {
        //
        // Can be ignored
        //
        // ShowMessages("err, in setting WaitCommEvent\n");
        // return FALSE;
    }
#else
    //
    // TODO(Linux): waiting for the first byte on the serial port is
    // Win32-only here (SetCommMask/WaitCommEvent); the Linux home for it is
    // platform-serial.c. Unreachable for now, as the Linux serial path is
    // refused in KdPrepareAndConnectDebugPort.
    //
#endif // _WIN32

    //
    // Read data and store in a buffer
    //
    do
    {
#ifdef _WIN32
        Status = ReadFile(g_SerialRemoteComPortHandle, &ReadData, sizeof(ReadData), &NoBytesRead, NULL);
#else
        //
        // Linux: read one byte through the cross-platform serial transport
        //
        Status = PlatformSerialReadByte(g_SerialRemoteComPortHandle,
                                        &ReadData,
                                        &NoBytesRead,
                                        PLATFORM_SERIAL_IO_DEBUGGEE);
#endif // _WIN32

        //
        // Check to make sure that we don't pass the boundaries
        //
        if (!Status || !(MaxSerialPacketSize > Loop))
        {
            //
            // Invalid buffer
            //
            ShowMessages("err, a buffer received in debuggee which exceeds the "
                         "buffer limitation\n");
            goto StartAgain;
        }

        SerialBuffer[Loop] = ReadData;

        if (KdCheckForTheEndOfTheBuffer(&Loop, (BYTE *)SerialBuffer))
        {
            break;
        }

        ++Loop;
    } while (NoBytesRead > 0);

    //
    // Because we used overlapped I/O on the other side, sometimes
    // the debuggee might cancel the read so it returns, if it returns
    // then we should restart reading again
    //
    if (Loop == 1 && SerialBuffer[0] == NULL)
    {
        //
        // Chunk data to cancel non async read
        //
        goto StartAgain;
    }

    //
    // Get actual length of received data
    //
    // ShowMessages("\nNumber of bytes received = %d\n", Loop);
    // for (size_t i = 0; i < Loop; i++) {
    //   ShowMessages("%x ", SerialBuffer[i]);
    // }
    // ShowMessages("\n");
    //

    if (TheActualPacket->Indicator == INDICATOR_OF_HYPERDBG_PACKET)
    {
        //
        // Check checksum
        //
        if (KdComputeDataChecksum((PVOID)&TheActualPacket->Indicator,
                                  Loop - sizeof(BYTE)) != TheActualPacket->Checksum)
        {
            ShowMessages("err checksum is invalid\n");
            goto StartAgain;
        }

        //
        // Check if the packet type is correct
        //
        if (TheActualPacket->TypeOfThePacket != DEBUGGER_REMOTE_PACKET_TYPE_DEBUGGER_TO_DEBUGGEE_EXECUTE_ON_USER_MODE)
        {
            //
            // sth wrong happened, the packet is not belonging to use
            // nothing to do, just wait again
            //
            ShowMessages("err, unknown packet received from the debugger\n");
            goto StartAgain;
        }

        //
        // It's a HyperDbg packet
        //
        switch (TheActualPacket->RequestedActionOfThePacket)
        {
        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_ON_USER_MODE_PAUSE:

            if (!DebuggerPauseDebuggee())
            {
                ShowMessages("err, debugger tries to pause the debuggee but the "
                             "attempt was unsuccessful\n");
            }

            break;

        case DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_ON_USER_MODE_DO_NOT_READ_ANY_PACKET:

            //
            // Not read anymore
            //
            return TRUE;

            break;

        default:

            ShowMessages("err, unknown packet action received from the debugger\n");

            break;
        }
    }
    else
    {
        //
        // It's not a HyperDbg packet, it's probably a GDB packet
        //
        PlatformDebugBreak();
    }

    //
    // Wait for debug pause command again
    //
    goto StartAgain;

    return TRUE;
}

/**
 * @brief Check if the remote debuggee needs to pause the system
 *
 * @param Param
 * @return BOOLEAN
 */
DWORD WINAPI
ListeningSerialPauseDebuggerThread(PVOID Param)
{
    //
    // Create a listening thead in debugger
    //
    ListeningSerialPortInDebugger();

    return 0;
}

/**
 * @brief Check if the remote debugger needs to pause the system
 *
 * @param SerialHandle
 * @return BOOLEAN
 */
DWORD WINAPI
ListeningSerialPauseDebuggeeThread(PVOID Param)
{
    //
    // Create a listening thead in debuggee
    //
    ListeningSerialPortInDebuggee();

    return 0;
}

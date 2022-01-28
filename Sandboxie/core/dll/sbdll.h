/*
 * Copyright 2004-2020 Sandboxie Holdings, LLC 
 * Copyright 2020-2021 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//---------------------------------------------------------------------------
// Sandboxie DLL
//---------------------------------------------------------------------------


#ifndef _MY_SBDLL_H
#define _MY_SBDLL_H


#include "sbieapi.h"


#ifdef __cplusplus
extern "C" {
#endif


#ifndef SBDLL_EXPORT
#define SBDLL_EXPORT  __declspec(dllexport)
#endif


//---------------------------------------------------------------------------
// Defines
//---------------------------------------------------------------------------


#define TokenElevationTypeNone 99

#define ENV_VAR_PFX            L"00000000_" SBIE L"_"
#define DATA_SLOTS 5
#define SESSION_PROCESS L"SboxSession"

typedef struct _PROCESS_DATA {
    ULONG tid;
    ULONG initFlag;
    HANDLE hStartLingerEvent;
    DWORD state;
    DWORD errorCode;
    DWORD checkpoint;
    WCHAR * name;
    WCHAR * EventName;
} PROCESS_DATA;

PROCESS_DATA *my_findProcessData(WCHAR *name,int createNew);

//---------------------------------------------------------------------------
// Functions (DllMain)
//---------------------------------------------------------------------------


SBDLL_EXPORT  void *SbDll_Hook(
    const char *SourceFuncName, void *SourceFunc, void *DetourFunc);

#define SBDLL_HOOK(pfx,proc)                  \
    *(ULONG_PTR *)&__sys_##proc = (ULONG_PTR)   \
        SbDll_Hook(#proc, proc, pfx##proc);   \
    if (! __sys_##proc) return FALSE;

SBDLL_EXPORT  void SbDll_DeviceChange(WPARAM wParam, LPARAM lParam);

SBDLL_EXPORT  const WCHAR *SbDll_GetDrivePath(ULONG DriveIndex);

SBDLL_EXPORT  const WCHAR *SbDll_GetUserPathEx(WCHAR which);

SBDLL_EXPORT  BOOLEAN SbDll_TranslateNtToDosPath(WCHAR *path);

SBDLL_EXPORT  BOOLEAN SbDll_StartSbieSvc(BOOLEAN retry);

SBDLL_EXPORT  const WCHAR *SbDll_GetStartError(void);

SBDLL_EXPORT  BOOLEAN SbDll_GetServiceRegistryValue(
    const WCHAR *name, void *kvpi, ULONG sizeof_kvpi);

SBDLL_EXPORT  ULONG SbDll_GetLanguage(BOOLEAN *rtl);

SBDLL_EXPORT  BOOLEAN SbDll_KillOne(ULONG ProcessId);

SBDLL_EXPORT  BOOLEAN SbDll_KillAll(
    ULONG SessionId, const WCHAR *BoxName);

SBDLL_EXPORT  ULONG SbDll_GetTokenElevationType(void);

SBDLL_EXPORT  WCHAR *SbDll_FormatMessage(ULONG code, const WCHAR **ins);

SBDLL_EXPORT  WCHAR *SbDll_FormatMessage0(ULONG code);

SBDLL_EXPORT  WCHAR *SbDll_FormatMessage1(ULONG code, const WCHAR *ins1);

SBDLL_EXPORT  WCHAR *SbDll_FormatMessage2(
    ULONG code, const WCHAR *ins1, const WCHAR *ins2);

SBDLL_EXPORT  BOOL SbDll_RunSandboxed(
    const WCHAR *box_name, const WCHAR *cmd, const WCHAR *dir,
    ULONG creation_flags, STARTUPINFO *si, PROCESS_INFORMATION *pi);

//---------------------------------------------------------------------------
// Functions (CallSvc)
//---------------------------------------------------------------------------


SBDLL_EXPORT  const WCHAR *SbDll_PortName(void);

SBDLL_EXPORT  struct _MSG_HEADER *SbDll_CallServer(
    struct _MSG_HEADER *req);

SBDLL_EXPORT  void *SbDll_CallServerQueue(
	const WCHAR* queue, void *req, ULONG req_len, ULONG rpl_min_len);

SBDLL_EXPORT  void SbDll_FreeMem(void *data);

SBDLL_EXPORT  ULONG SbDll_QueueCreate(
    const WCHAR *QueueName, HANDLE *out_EventHandle);

SBDLL_EXPORT  ULONG SbDll_QueueGetReq(
    const WCHAR *QueueName, ULONG *out_ClientPid, ULONG *out_ClientTid,
    ULONG *out_RequestId, void **out_DataPtr, ULONG *out_DataLen);

SBDLL_EXPORT  ULONG SbDll_QueuePutRpl(
    const WCHAR *QueueName, ULONG RequestId, void *DataPtr, ULONG DataLen);

SBDLL_EXPORT  ULONG SbDll_QueuePutReq(
    const WCHAR *QueueName, void *DataPtr, ULONG DataLen,
    ULONG *out_RequestId, HANDLE *out_EventHandle);

SBDLL_EXPORT  ULONG SbDll_QueueGetRpl(
    const WCHAR *QueueName, ULONG RequestId,
    void **out_DataPtr, ULONG *out_DataLen);

SBDLL_EXPORT  ULONG SbDll_UpdateConf(
    WCHAR OpCode, const WCHAR *Password, const WCHAR *Section,
    const WCHAR *Setting, const WCHAR *Value);

SBDLL_EXPORT  ULONG SbDll_QueryConf(
    const WCHAR *Section, const WCHAR *Setting,
    ULONG setting_index, WCHAR *out_buffer, ULONG buffer_len);

//---------------------------------------------------------------------------
// Functions (Other)
//---------------------------------------------------------------------------


SBDLL_EXPORT  BOOLEAN SbDll_StartCOM(BOOLEAN Async);

SBDLL_EXPORT  BOOLEAN SbDll_IsOpenCOM(void);

SBDLL_EXPORT  BOOLEAN SbDll_IsDirectory(const WCHAR *PathW);

SBDLL_EXPORT  void *SbDll_InitPStore(void);

SBDLL_EXPORT  ULONG SbDll_GetHandlePath(
    HANDLE FileHandle, WCHAR *OutWchar8192, BOOLEAN *IsBoxedPath);

SBDLL_EXPORT  BOOLEAN SbDll_RunFromHome(
    const WCHAR *pgmName, const WCHAR *pgmArgs,
    STARTUPINFOW *si, PROCESS_INFORMATION *pi);

SBDLL_EXPORT  WCHAR *SbDll_AssocQueryCommand(const WCHAR *subj);

SBDLL_EXPORT  WCHAR *SbDll_AssocQueryProgram(const WCHAR *subj);

SBDLL_EXPORT  BOOLEAN SbDll_IsBoxedService(HANDLE hService);

SBDLL_EXPORT  BOOL SbDll_StartBoxedService(
    const WCHAR *ServiceName, BOOLEAN WithAdd);

SBDLL_EXPORT  BOOL SbDll_CheckProcessLocalSystem(HANDLE ProcessHandle);

SBDLL_EXPORT  HRESULT SbDll_ComCreateProxy(
    REFIID riid, void *pUnkOuter, void *pChannel, void **ppUnknown);

SBDLL_EXPORT  HRESULT SbDll_ComCreateStub(
    REFIID riid, void *pUnknown, void **ppStub, void **ppChannel);

SBDLL_EXPORT  BOOLEAN SbDll_IsOpenClsid(
    REFCLSID rclsid, ULONG clsctx, const WCHAR *BoxName);

SBDLL_EXPORT  void SbDll_DisableElevationHook(void);

SBDLL_EXPORT  BOOLEAN SbDll_RegisterDllCallback(void *Callback);

SBDLL_EXPORT  BOOLEAN SbDll_ExpandAndRunProgram(const WCHAR *Command);


SBDLL_EXPORT  ULONG SbDll_InjectLow_InitHelper();
SBDLL_EXPORT  ULONG SbDll_InjectLow_InitSyscalls(BOOLEAN drv_init);
SBDLL_EXPORT  ULONG SbDll_InjectLow(HANDLE hProcess, ULONG init_flags, BOOLEAN dup_drv_handle);


SBDLL_EXPORT  BOOLEAN SbDll_MatchImage(const WCHAR* pat_str, const WCHAR* test_str, const WCHAR* BoxName);

SBDLL_EXPORT  BOOLEAN SbDll_GetStringForStringList(const WCHAR* string, const WCHAR* boxname, const WCHAR* setting, WCHAR* value, ULONG value_size);
SBDLL_EXPORT  BOOLEAN SbDll_CheckStringInList(const WCHAR* string, const WCHAR* boxname, const WCHAR* setting);

SBDLL_EXPORT  BOOLEAN SbDll_GetSettingsForName(
    const WCHAR* boxname, const WCHAR* name, const WCHAR* setting, WCHAR* value, ULONG value_size, const WCHAR* deftext);

SBDLL_EXPORT  BOOLEAN SbDll_GetSettingsForName_bool(
    const WCHAR* boxname, const WCHAR* name, const WCHAR* setting, BOOLEAN defval);

SBDLL_EXPORT  BOOLEAN SbDll_GetBorderColor(const WCHAR* box_name, COLORREF* color, BOOL* title, int* width);

SBDLL_EXPORT  BOOLEAN SbDll_IsReservedFileName(const WCHAR* name);

//---------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif /* _MY_SBDLL_H */

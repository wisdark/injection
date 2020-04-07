/**
  Copyright © 2019 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
#ifndef ETW_H
#define ETW_H

#include "../ntlib/util.h"
#include "../ntlib/ntddk.h"

#include <evntrace.h>
#include <pla.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <Evntcons.h>

typedef enum _ETW_NOTIFICATION_TYPE {
    EtwNotificationTypeNoReply = 1,
    EtwNotificationTypeLegacyEnable = 2,
    EtwNotificationTypeEnable = 3,
    EtwNotificationTypePrivateLogger = 4,
    EtwNotificationTypePerflib = 5,
    EtwNotificationTypeAudio = 6,
    EtwNotificationTypeSession = 7,
    EtwNotificationTypeReserved = 8,
    EtwNotificationTypeCredentialUI = 9,
    EtwNotificationTypeInProcSession = 10,
    EtwNotificationTypeMax = 11,
} ETW_NOTIFICATION_TYPE;


typedef struct _MCGEN_TRACE_CONTEXT {
    TRACEHANDLE      RegistrationHandle;
    TRACEHANDLE      Logger;
    ULONGLONG        MatchAnyKeyword;
    ULONGLONG        MatchAllKeyword;
    ULONG            Flags;
    ULONG            IsEnabled;
    UCHAR            Level;
    UCHAR            Reserve;
    USHORT           EnableBitsCount;
    PULONG           EnableBitMask;
    const ULONGLONG* EnableKeyWords;
    const UCHAR*     EnableLevel;
} MCGEN_TRACE_CONTEXT, *PMCGEN_TRACE_CONTEXT;

typedef struct _RTL_BALANCED_NODE {
    union {
      struct _RTL_BALANCED_NODE *Children[2];
      struct {
        struct _RTL_BALANCED_NODE *Left;
        struct _RTL_BALANCED_NODE *Right;
      };
    };
    union {
      UCHAR     Red:1;
      UCHAR     Balance:2;
      ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef NTSTATUS (*PETWENABLECALLBACK) (
  LPCGUID                  SourceId,
  ULONG                    ControlCode,
  UCHAR                    Level,
  ULONGLONG                MatchAnyKeyword,
  ULONGLONG                MatchAllKeyword,
  PEVENT_FILTER_DESCRIPTOR FilterData,
  PVOID                    CallbackContext);

typedef struct _RTL_RB_TREE {
  struct _RTL_BALANCED_NODE* Root;
  union {
    UCHAR Encoded:1; /* bit position: 0 */
    struct _RTL_BALANCED_NODE* Min;
  };
} RTL_RB_TREE, *PRTL_RB_TREE;
    
typedef struct _ETW_USER_REG_ENTRY {
  RTL_BALANCED_NODE  Nodes;
  ULONG64            Padding1;
  GUID               ProviderId;
  PETWENABLECALLBACK Callback;
  PVOID              CallbackContext;
  SRWLOCK            RegistrationLock;
  SRWLOCK            NodeLock;
  HANDLE             UniqueThread;
  ULONG64            Unknown3;
  USHORT             Index;
  USHORT             Type;
  ULONG64            Unknown[19];
} ETW_USER_REG_ENTRY, *PETW_USER_REG_ENTRY;

#ifdef __cplusplus
extern "C" {
#endif

  BSTR etw_id2name(OLECHAR *id);
  BOOL etw_disable(HANDLE hp, RTL_BALANCED_NODE *node, USHORT index); 
  VOID etw_reg_info(HANDLE hp, RTL_BALANCED_NODE *node, PETW_USER_REG_ENTRY re, int tabs);
  VOID etw_dump_nodes(HANDLE hp, RTL_BALANCED_NODE *node, PWCHAR dll, int opt, int tabs);
  VOID etw_search_process(HANDLE hp, PPROCESSENTRY32 pe32, LPVOID etw, PWCHAR dll, int opt);
  LPVOID etw_get_table_va(VOID);
  RTL_BALANCED_NODE *etw_get_reg(HANDLE hp, LPVOID etw, PWCHAR prov, PETW_USER_REG_ENTRY re); 
  BOOL etw_inject(DWORD pid, PWCHAR path, PWCHAR prov);
  BOOL etw_disable(HANDLE hp, RTL_BALANCED_NODE *node, USHORT index);
  VOID etw_search_system(DWORD pid, PWCHAR dll, PWCHAR prov, int opt);

#ifdef __cplusplus
}
#endif
    
#endif

/**
  Copyright © 2020 Odzhan. All Rights Reserved.

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

#ifndef WER_H
#define WER_H

typedef struct _WER_METADATA {
    PVOID                Next;
    WCHAR                Key[64];
    WCHAR                Value[128];
} WER_METADATA, *PWER_METADATA;

typedef struct _WER_FILE {
    USHORT               Flags;
    WCHAR                Path[MAX_PATH];
} WER_FILE, *PWER_FILE;

typedef struct _WER_MEMORY {
    PVOID                Address;
    ULONG                Size;
} WER_MEMORY, *PWER_MEMORY;

typedef struct _WER_GATHER {
    PVOID                Next;
    USHORT               Flags;    
    union {
      WER_FILE           File;
      WER_MEMORY         Memory;
    } v;
} WER_GATHER, *PWER_GATHER;

typedef struct _WER_DUMP_COLLECTION {
    PVOID                Next;
    DWORD                ProcessId;
    DWORD                ExtraInfoForThreadId;
} WER_DUMP_COLLECTION, *PWER_DUMP_COLLECTION;

typedef struct _WER_RUNTIME_DLL {
    PVOID                Next;
    ULONG                Length;
    PVOID                Context;
    WCHAR                CallbackDllPath[MAX_PATH];
} WER_RUNTIME_DLL, *PWER_RUNTIME_DLL;

typedef struct _WER_RECOVERY_INFO {
    ULONG                Length;
    PVOID                Callback;
    PVOID                Parameter;
    HANDLE               StartedEvent;
    HANDLE               FinishedEvent;
    HANDLE               InProgressEvent;
    LONG                 LastError;
    BOOL                 bRecoverySuccess;
    DWORD                PingInterval;
    DWORD                Flags;
} WER_RECOVERY_INFO, *PWER_RECOVERY_INFO;

typedef struct _WER_HEAP_MAIN_HEADER {
    WCHAR                Signature[16];                // HEAP_SIGNATURE 
    LIST_ENTRY           ListHead;
    HANDLE               Mutex;
    PVOID                Unknown1;
    PVOID                Unknown2;
} WER_HEAP_MAIN_HEADER, *PWER_HEAP_MAIN_HEADER;

typedef struct _WER_PEB_HEADER_BLOCK {
    LONG                 Length;
    WCHAR                Signature[16];                // PEB_SIGNATURE
    LONG                 Flag;
    WCHAR                AppDataRelativePath[64];
    WCHAR                RestartCommandLine[MAX_PATH]; // Used in command line for a restart
    ULONG64              Unknown1[191];
    WER_RECOVERY_INFO    RecoveryInfo;
    PWER_GATHER          GatherList;                   // List of memory addresses and files
    PWER_METADATA        MetaDataList;
    PWER_RUNTIME_DLL     RuntimeDllList;               // User-defined modules
    PWER_DUMP_COLLECTION DumpCollectionList;
    LONG                 GatherCount;
    LONG                 MetaDataCount;
    LONG                 DumpCount;
    LONG                 Flags;
    WER_HEAP_MAIN_HEADER MainHeader;
    PVOID                Reserved;
} WER_PEB_HEADER_BLOCK, *PWER_PEB_HEADER_BLOCK;

#endif

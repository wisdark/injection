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
  
#define UNICODE
#include "../ntlib/util.h"

#include "wer.h"

PWCHAR get_mapped_file(HANDLE hp, PVOID address) {
    static WCHAR path[MAX_PATH];
    ZeroMemory(path, sizeof(path));
    
    GetMappedFileName(hp, address, path, MAX_PATH);
    return path;
}
          
void recovery_info(PWER_RECOVERY_INFO ri) {
    
    if(ri->Length == 0) return;
    
    printf("Recovery Info : %p\n", ri);
    
    printf("Length           : %i\n", ri->Length);
    printf("Callback         : %p\n", ri->Callback);
    printf("Parameter        : %p\n", ri->Parameter); 
    printf("StartedEvent     : %p\n", ri->StartedEvent); 
    printf("FinishedEvent    : %p\n", ri->FinishedEvent); 
    printf("InProgressEvent  : %p\n", ri->InProgressEvent); 
    printf("LastError        : %08lx\n", ri->LastError); 
    printf("bRecoverySuccess : %i\n", ri->bRecoverySuccess); 
    printf("PingInterval     : %08lx\n", ri->PingInterval); 
    printf("Flags            : %08lx\n", ri->Flags); 
}

void gather_info(HANDLE hp, PVOID List, DWORD Count) {
    WER_GATHER wg;
    PVOID      ptr;
    SIZE_T     rd;
    
    if(List == NULL || Count == 0) return;
    ptr = List;
    
    printf("GatherList : %p\n", List);
    
    for(;;) {
      ReadProcessMemory(
        hp, ptr, &wg, 
        sizeof(wg), &rd);
      
      if(rd != sizeof(wg)) break;
      
      if((wg.Flags & 0xC000) == 0x4000) {
        printf("File       : %ws\n", wg.v.File.Path);
      } else {
        if(wg.Flags & 0x8000) {
          printf("** HIDDEN **\n");
        }
        ptr = (PVOID)wg.v.Memory.Address;
        printf("Size       : %i\n", wg.v.Memory.Size); 
        printf("Address    : %p %ws\n", ptr, get_mapped_file(hp, ptr));
      }
      printf("******************************\n");
      if(wg.Next == 0) break;
      ptr = (PVOID)wg.Next;
    }
    putchar('\n');
}

void metadata_info(HANDLE hp, PVOID List, DWORD Count) {
    WER_METADATA md;
    PVOID        ptr;
    SIZE_T       rd;
    
    if(List == NULL || Count == 0) return;
    ptr = List;
    
    printf("MetaDataList : %p\n", List);
    
    for(;;) {
      ReadProcessMemory(
        hp, ptr, &md, 
        sizeof(md), &rd);
      
      if(rd != sizeof(md)) break;
      
      printf("Key   : %ws\n", md.Key);
      printf("Value : %ws\n", md.Value);
    
      if(md.Next == 0) break;
      ptr = (PVOID)md.Next;
    }
    putchar('\n');
}

void runtime_info(HANDLE hp, PVOID List) {
    WER_RUNTIME_DLL rt;
    PVOID           ptr;
    SIZE_T          rd;
    
    if(List == NULL) return;
    ptr = List;
    
    printf("RuntimeList : %p\n", List);
    
    for(;;) {
      ReadProcessMemory(
        hp, ptr, &rt, 
        sizeof(rt), &rd);
      
      if(rd != sizeof(rt)) break;
      
      printf("Context      : %p\n",  (PVOID)rt.Context);
      printf("Callback DLL : %ws\n", (PWCHAR)rt.CallbackDllPath);
    
      if(rt.Next == 0) break;
      ptr = (PVOID)rt.Next;
    }
    putchar('\n');
}

void dump_info(HANDLE hp, PVOID List, DWORD Count) {
    WER_DUMP_COLLECTION dc;
    PVOID               ptr;
    SIZE_T              rd;
    
    if(List == NULL || Count == 0) return;
    ptr = List;
    
    printf("DumpCollectionList : %p\n", List);
    
    for(;;) {
      ReadProcessMemory(
        hp, ptr, &dc, 
        sizeof(dc), &rd);
      
      if(rd != sizeof(dc)) break;
      
      printf("Process ID : %p\n", (PVOID)dc.ProcessId);
      printf("Thread ID  : %ws\n", (PWCHAR)dc.ExtraInfoForThreadId);
    
      if(dc.Next == 0) break;
      ptr = (PVOID)dc.Next;
    }
    putchar('\n');
}

void wer_dump(HANDLE hp, DWORD pid, PWCHAR proc) {
    NTSTATUS                  nts;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG                     len;
    PEB                       peb;
    SIZE_T                    rd;
    WER_PEB_HEADER_BLOCK      wer;
    
    nts = NtQueryInformationProcess(
      hp, ProcessBasicInformation,
      &pbi, sizeof(pbi), &len);
    
    ReadProcessMemory(
      hp, pbi.PebBaseAddress,
      &peb, sizeof(PEB), &rd);
     
    if(peb.WerRegistrationData != NULL) {
      wprintf(L"\nWerRegistrationData : %p [%04i] %s\n", 
        peb.WerRegistrationData, pid, proc);
        
      ReadProcessMemory(
        hp, peb.WerRegistrationData,
        &wer, sizeof(wer), &rd);
        
      if(wer.AppDataRelativePath[0] != 0)
        printf("localAppDataRelativePath : %ws\n", wer.AppDataRelativePath);
      
      if(wer.RestartCommandLine[0] != 0) 
        printf("RestartCommandLine  : %ws\n", wer.RestartCommandLine);
      
      gather_info(hp, (PVOID)wer.GatherList, wer.GatherCount);
      metadata_info(hp, (PVOID)wer.MetaDataList, wer.MetaDataCount);
      runtime_info(hp, (PVOID)wer.RuntimeDllList);
      dump_info(hp, (PVOID)wer.DumpCollectionList, wer.DumpCount);
      recovery_info(&wer.RecoveryInfo);
    }
}

void scan_system(DWORD pid) {
    HANDLE         ss;
    PROCESSENTRY32 pe;
    HANDLE         hp;
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(ss == INVALID_HANDLE_VALUE) return;
    
    pe.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(ss, &pe)){
      do {
        // skip system
        if(pe.th32ProcessID <= 4) continue;
        
        // if filtering by process id, skip entries that don't match
        if(pid != 0 && pe.th32ProcessID != pid) continue;
        
        // try open process
        hp = OpenProcess(
          PROCESS_ALL_ACCESS, 
          FALSE, 
          pe.th32ProcessID);
          
        if(hp != NULL) {
          wer_dump(hp, pe.th32ProcessID, pe.szExeFile);
          
          CloseHandle(hp);
        }
      } while(Process32Next(ss, &pe));
    }
    CloseHandle(ss);
}

int main(void) {
    WCHAR **argv, *process=NULL;
    int   argc, pid=0;
    
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    if(argc == 2) {
      pid = name2pid(argv[1]);
      if(pid == 0) pid = wcstoull(argv[1], NULL, 10);
      if(pid == 0) {
        wprintf(L"  [ ERROR: Unable to resolve pid for \"%s\".\n", argv[1]);
        return -1;
      }
    }
    
    // try enable debug privilege
    if(!SetPrivilege(SE_DEBUG_NAME, TRUE)) {
      wprintf(L"  [ WARNING: Failed to enable debugging privilege.\n");
    }
    
    scan_system(pid);
    printf("Finished.\n");
    return 0;
}
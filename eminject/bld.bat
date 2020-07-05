@echo off
yasm -fbin -DBIN calc3.asm -ocalc3.bin
disasm calc3.bin >calc3.h
yasm -fbin -DBIN calc4.asm -ocalc4.bin
disasm calc4.bin >calc4.h
yasm -fwin64 calc3.asm -ocalc3.obj
cl /c demo.c
link /LARGEADDRESSAWARE:NO demo.obj calc3.obj
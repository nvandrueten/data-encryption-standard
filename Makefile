CC = gcc
RCC = riscv64-unknown-elf-gcc
CFLAGS = -g -O0 -static -Wall -Wextra #-Werror
 
RCFLAGS = -DPREALLOCATE=1 -mcmodel=medany -static -std=gnu99 -O0 -ffast-math -fno-common -fno-builtin-printf -static -nostdlib -nostartfiles -lm -lgcc -I/home/niels/gitrepos/param/core/c-class/verification/riscv-tests/env -I/home/niels/gitrepos/param/core/c-class/verification/riscv-tests/benchmarks/common -T/home/niels/gitrepos/param/core/c-class/verification/riscv-tests/benchmarks/common/test.ld

BUILDFILES = syscalls.c crt.S

COBJ = desfulltest.elf 
RISCVOBJ = des.riscv

all: c riscv

desonline.riscv: ${DESONLINEJOBS} ; echo "$@ success"
desoffline.elf: ${DESOFFLINEJOBS} ; echo "$@ success"


${DESONLINEJOBS}: desjob%: ; $(RCC) $(RCFLAGS) -DROUND=$* -DFIRSTROUNDONLY syscalls.c crt.S des.c -o des.riscv;
		elf2hex 8 4194304 des.riscv 2147483648 > des.riscv.hex
		cp des.riscv.hex /home/niels/gitrepos/param/core/c-class/bin/code.mem
		cd /home/niels/gitrepos/param/core/c-class/bin/ && ./out +trace
		cp /home/niels/gitrepos/param/core/c-class/bin/logs/vlt_dump.vcd /media/niels/Elements/research/vcd_files/round_$*.vcd 
		rm des.riscv
		
${DESOFFLINEJOBS}: desjot%: ; $(CC) $(CFLAGS) -DTEST -DROUND=$* -DFIRSTROUNDONLY des.c -o des.elf
		./des.elf
		rm des.elf
c: $(COBJ)

riscv: $(RISCVOBJ) 


des1round.elf: des.c
	$(CC) $(CFLAGS) -DROUND=0 -DTEST -DFIRSTROUNDONLY $^ -o $@

desfull.elf: des.c
	$(CC) $(CFLAGS) -DROUND=0 $^ -o $@
	
desfulltest.elf: des.c
	$(CC) $(CFLAGS) -DROUND=300 -DTEST $^ -o $@
	

des.riscv: $(BUILDFILES) des.c 
	$(RCC) $(RCFLAGS) -DROUND=0 -DFIRSTROUNDONLY $^ -o $@
	riscv64-unknown-elf-objdump --disassemble-all --disassemble-zeroes --section=.text --section=.text.startup --section=.data $@ > $@.dump
	elf2hex 8 4194304 $@ 2147483648 > $@.hex
	
clean:
	rm -rf *.riscv *.elf *.txt *.hex *.dump

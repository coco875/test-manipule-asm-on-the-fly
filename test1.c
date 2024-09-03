/* test1.c */

#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

void hook_add(void);

int add(int a, int b) {
    hook_add();
    return a+b;
}

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm(handle, (void*) &add, 30, (uint64_t) (void*) &add, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else {
		printf("ERROR: Failed to disassemble given code!\n");
    }

	cs_close(&handle);

    return 0;
}

void hook_add(void) {
    printf("hello world\n");
    asm(
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
    );
}

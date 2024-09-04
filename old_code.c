void construct_hook_function(ks_engine *ks, char* code_buffer, char *type, int num_arg, void* hook, void* original_function, char* out_function_data){
    unsigned char *encode;
    size_t size;
	size_t count;

    int size_stack = 0;
    for (int i = 0; i<num_arg; i++) {
        size_stack += (type[i]+1)*4;
    }
    size_stack = around_power_2(size_stack);
    printf("the size of the stack are %d\n", size_stack);

    sprintf(code_buffer, "push rbp; mov	rbp, rsp; sub rsp, %d;\n", size_stack);

    size_stack = 0;
    for (int i = 0; i<num_arg; i++) {
        size_stack+=((type[i]+1)*4);
        sprintf(code_buffer, "%s mov DWORD PTR [rbp-%d], %s;\n", code_buffer, size_stack, registre_name[type[i]][i]);
    }
    
    sprintf(code_buffer, "%s call 0x%lx;\n", code_buffer, hook);

    size_stack = 0;
    for (int i = 0; i<num_arg; i++) {
        size_stack+=((type[i]+1)*4);
        sprintf(code_buffer, "%s mov %s, DWORD PTR [rbp-%d];\n", code_buffer, registre_name[type[i]][i], size_stack);
    }

    sprintf(code_buffer, "%s call 0x%lx; leave; ret;\n", code_buffer, original_function);
    convert_asm(ks, code_buffer, (uint64_t) out_function_data, &encode, &size, &count);

    unprotect_memory(out_function_data, size);
    memcpy(out_function_data, encode, size);
    ks_free(encode);
}

{
    count = cs_disasm(handle, (void*) &add, 30, (uint64_t) (void*) &add, 0, &insn);
	if (count <= 0) {
		printf("ERROR: Failed to disassemble given code!\n");
        cs_close(&handle);
        exit(-1);
    }
    size_t j;
    for (j = 0; j < count; j++) {
        printf("0x%"PRIx64":\tsize:%ld\t%s\t\t%s\n", insn[j].address, insn[j].size, insn[j].mnemonic,
                insn[j].op_str);
    }

    char code[1024];
    size_t size_function = 4096;
    void *lambda_function = malloc(size_function);
    sprintf(code, "jmp %ld", lambda_function);
    convert_asm(ks, code, (uint64_t) add, &encode, &size, &count);

    unprotect_memory(&add, size);
    memcpy(&add, encode, size);
    ks_free(encode);

    void *original_function = malloc(size_function);

    sprintf(code, "");

    size_t size_junk = 0;
    int i = 0;
    while (size>size_junk) {
        sprintf(code,"%s %s %s;", code, insn[i].mnemonic, insn[i].op_str);
        size_junk += insn[i].size;
        i++;
    }

    sprintf(code, "%s jmp 0x%lx;", code, insn[i].address);
    convert_asm(ks, code, (uint64_t) original_function, &encode, &size, &count);

    unprotect_memory(original_function, size);
    memcpy(original_function, encode, size);
    ks_free(encode);
}
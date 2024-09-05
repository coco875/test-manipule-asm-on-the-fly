# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone
KEYSTONE_LDFLAGS = -lkeystone -lstdc++ -lm
CC = clang

test1: test1.o
	${CC} $< -gdwarf -O3 -Wall -l$(LIBNAME) -o $@ $(KEYSTONE_LDFLAGS)

%.o: %.c
	${CC} -S -masm=intel $< -o $@.s
	${CC} -c -gdwarf -Wall $< -o $@

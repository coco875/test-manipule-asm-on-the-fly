# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone
KEYSTONE_LDFLAGS = -lkeystone -lstdc++ -lm

test1: test1.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@ $(KEYSTONE_LDFLAGS)
	objdump -S --disassemble test1 > $@.s

%.o: %.c
	${CC} -c $< -o $@
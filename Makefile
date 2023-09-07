CFLAGS= -O2 -Warray-bounds -Wsequence-point -Walloc-zero -Wnull-dereference -Wpointer-arith -Wcast-qual -Wcast-align=strict -fanalyzer
CLANGFLAGS= -fsyntax-only -Wall -Wextra -Wuninitialized -Wpointer-arith -Wcast-qual -Wcast-align
CLANGTIDYFLAGS= -checks=cert-*,-clang-analyzer-*
CPPFLAGS= -I include/
LDFLAGS= -lbfd

all: isos_inject isos_inject_addr isos_inject_mem isos_inject_clang copy binary_compilation

binary_compilation:
	nasm -f bin -o inject inject.asm

copy:
	@cp -f date tests/test_date

isos_inject: isos_inject.o parsing.o overwrite.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@mv -f $@ bin/

isos_inject_clang: src/isos_inject.c src/parsing.c src/overwrite.c
	clang $(CLANGFLAGS) $(CPPFLAGS) $^

isos_inject_addr: src/isos_inject.c src/parsing.c src/overwrite.c
	clang -fsanitize=address -fsanitize=undefined $(CPPFLAGS) -o $@ $^ $(LDFLAGS)
	@mv -f $@ bin/

isos_inject_mem: src/isos_inject.c src/parsing.c src/overwrite.c
	clang -fsanitize=memory -fsanitize=undefined $(CPPFLAGS) -o $@ $^ $(LDFLAGS)
	@mv -f $@ bin/

isos_inject.o: src/isos_inject.c include/parsing.h include/overwrite.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
	clang-tidy $(CLANGTIDYFLAGS) $<

parsing.o: src/parsing.c include/parsing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
	clang-tidy $(CLANGTIDYFLAGS) $<

overwrite.o: src/overwrite.c include/overwrite.h include/parsing.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
	clang-tidy $(CLANGTIDYFLAGS) $<

clean:
	rm -f *.o bin/isos* tests/test_date inject

help:
	@echo "Usage:"
	@echo " make [all]\t\t\tRun the whole build of isos_inject with gcc and clang"
	@echo " make isos_inject\t\tRun the whole build of isos_inject with gcc"
	@echo " make isos_inject_clang\t\tCheck errors and warnings with clang"
	@echo " make isos_inject_addr\t\tRun the whole build of isos_inject with clang and address sanitization"
	@echo " make isos_inject_mem\t\tRun the whole build of isos_inject with clang and memory sanitization"
	@echo " make clean\t\t\tRemove all files producted by the compilation"
	@echo " make help\t\t\tDisplay this help"

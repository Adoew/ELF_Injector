# ELF Injector project

The original binary "date" is at the root of the project.

The Makefile copies the orignal binary into the tests directory and rename it "test_date". The injection occurs on this binary.

There are three injector binaries generated in the bin directory :

- isos_inject is the binary compiled with all the warnings
- isos_inject_mem is the memory sanitized binary with clang (+ undefined behaviours)
- isos_inject_addr is the address sanitized binary with clang (+ undefined behaviours)

The injected raw binary is generated with nasm via the Makefile.

### Typical commands to use the injector

./isos_inject ../tests/test_date ../inject test 8388608 1

- The ELF file is test_date
- The binary to be injected is inject
- The new section name is test
- The base address of the section is 8388608 (address specified in decimal and not hexadecimal)
- The modified bit is set to 0 (ie. entry point change)

./isos_inject ../tests/test_date ../inject test 8388608 0

- The ELF file is test_date
- The binary to be injected is inject
- The new section name is test
- The base address of the section is 8388608 (address specified in decimal and not hexadecimal)
- The modified bit is set to 0 (ie. GOT override)

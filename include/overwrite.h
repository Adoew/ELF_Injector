#pragma once

#include <elf.h>

#include <stdlib.h>
#include <stdint.h>

/* Create a modified section header from the binary's .note.ABI-tag section header
   Returns -1 if the file could not be opened or if mmap failed
   Returns the file offset to the .note.ABI-tag section header otherwise */
int create_section_header(char *filename, Elf64_Ehdr *eheader, Elf64_Shdr *sheader, int index);

/* Write the modified section header at the spot of the original .note.ABI-tag section header
   Returns -1 in case of an error, 0 otherwise */
int write_section_header(char *filename, off_t offset, Elf64_Shdr *sheader, Elf64_Ehdr *eheader);

/* Sort the section header list and rewrite it into filename
   Returns -1 in case of an error, 0 otherwise */
int sort_and_write_shdr_list(char *filename, int offset, Elf64_Ehdr *eheader, Elf64_Shdr *list, int index, int move);

/* Write the section name name for the associated section header sheader into the .shstrtab
   Returns -1 in case of an error, 0 otherwise */
int write_section_name(char *filename, char *name, Elf64_Ehdr *eheader, Elf64_Shdr *sheader);

/* Overwrite the PT_NOTE program header. Returns -1 in case of an error, 0 otherwise. */
int write_pt_note(char *filename, Elf64_Ehdr *eheader, Elf64_Shdr *sheader, int index);

/* Overwrite the executable header of filename by changing its e_entry value by entry.
   Returns -1 in case of an error, 0 otherwise. */
int write_exec_header(char *filename, Elf64_Ehdr *eheader, uint64_t entry);

/* Write address at offset in the GOT (.got.plt section).
   Returns -1 in case of an error, 0 otherwise */
int got_hijack(char *filename, uint64_t address, uint64_t offset);
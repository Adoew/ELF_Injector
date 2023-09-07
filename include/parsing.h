#pragma once

#include <elf.h>

#include <stdlib.h>
#include <stdint.h>

#define ELF_EHEADER_SIZE 64
#define ELF_EHEADER_EIDENT_SIZE 16

/* Get the index of the first program header of type PT_NOTE
   Returns -1 if there is a memory mapping error
   Returns -2 if the PT_NOTE segment header is not found */
int get_pt_note_index(char *filename, Elf64_Ehdr *eheader);

/* Get the index of the section header describing the .shstrtab
   section from the execuatble header eheader */
int get_shstrtab_index(Elf64_Ehdr *eheader);

/* Get the index of the section header corresponding to section_name
   Returns -1 in case of an error with mmap or open
   Returns -2 if the section was not found */
int get_section_header_index(char *filename, Elf64_Ehdr *eheader, char *section_name);

/* Get the address field of the previous and next section headers of the section header
   identified with index to compare them with the address of sheader.
   Returns -1 in case of an error
   Returns 0 if we don't need to move sheader
   Returns 1 if we need to move left sheader
   Returns 2 if we need to move right sheader */
int get_closest_addresses(char *filename, Elf64_Ehdr *eheader, Elf64_Shdr *sheader, int index);

/* Get the list of the section headers of filename.
   Returns -1 in case of an error with mmap or open, 0 otherwise */
int get_shdr_list(char *filename, Elf64_Ehdr *eheader, Elf64_Shdr *list);

/* Get the offset in filename of the section name related to sheader
   Returns -1 in case of an error of mmap or open
   Returns the offset in the string table related to sheader otherwise */
int get_section_name_offset(char *filename, Elf64_Ehdr *eheader, Elf64_Shdr *sheader);

/* Get the sh_offset field of the section header starting at index.
   Returns -1 in case of an error with mmap or open, returns the offset otherwise. */
int get_section_header_offset(char *filename, Elf64_Ehdr *eheader, int index);
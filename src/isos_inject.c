#include <argp.h>
#include <bfd.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/overwrite.h"
#include "../include/parsing.h"

static const char doc[] = "isos_inject : an ELF binary code injecter";

static const char args_doc[] =
    "ELF_file binary section_name base_address modified";

static struct argp_option options[] = {
    {0, 0, 0, 0, 0, 0}};

struct arguments
{
  char *args[5];
};

/* Parsing function of each argument */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;

  switch (key)
  {
  case ARGP_KEY_ARG:
    if (state->arg_num >= 5)
      argp_usage(state);

    arguments->args[state->arg_num] = arg;
    break;

  case ARGP_KEY_END:
    if (state->arg_num < 5)
      argp_usage(state);

    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

int main(int argc, char **argv)
{
  struct arguments arguments;
  char *elf_file;
  char *binary;
  char *section_name;
  char *str_base_addr;
  char *str_modified;
  uint64_t base_address;
  bool modified;

  /* Parsing arguments */
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  elf_file = arguments.args[0];
  binary = arguments.args[1];
  section_name = arguments.args[2];
  base_address = strtol(arguments.args[3], &str_base_addr, 10);
  modified = strtol(arguments.args[4], &str_modified, 10);

  char *targeted_section = ".note.ABI-tag";
  if (strlen(section_name) > strlen(targeted_section))
    errx(EXIT_FAILURE, "Chosen name for the section too long ! \
         Please choose a name of length equal or less than %lu.\n",
         strlen(targeted_section));

  /* Initialize the bfd library */
  size_t init = bfd_init();
  if (init != BFD_INIT_MAGIC)
    errx(EXIT_FAILURE, "Failed initialization of libbfd");

  /* Opening the file and initializing its associate bfd */
  bfd *bfd = bfd_openr(elf_file, NULL);
  if (!bfd)
    errx(EXIT_FAILURE, "Can't open the ELF file !");

  /* Checking if the first argument has an ELF format */
  if (!bfd_check_format(bfd, bfd_object))
    errx(EXIT_FAILURE, "Wrong type ! Not an object file !");

  /* Checking if the first argument is an ELF file */
  if (bfd_get_flavour(bfd) != bfd_target_elf_flavour)
    errx(EXIT_FAILURE, "Wrong file type ! Not an ELF file !");

  /* Checking if the first argument is an executable file */
  if ((bfd_get_file_flags(bfd) & EXEC_P) == 0)
    errx(EXIT_FAILURE, "Wrong type ! Not an executable file !");

  /* Checking if the first argument is an ELF64 */
  const int arch = bfd_get_arch_size(bfd);
  if (arch != 64)
    errx(EXIT_FAILURE, "Wrong architecture : not an ELF64");

  bfd_close(bfd);

  printf("[+] ELF File : %s\n", elf_file);
  printf("[+] Binary : %s\n", binary);
  printf("[+] Name of the new section : %s\n", section_name);
  printf("[+] Base address : %ld\n", base_address);
  if (modified)
    printf("[+] Entry function modified : YES\n");

  else
    printf("[+] Entry function modified : NO\n");

  int fd;
  fd = open(elf_file, O_RDONLY);
  if (!fd)
    errx(EXIT_FAILURE, "Cannot open file !");

  /* Parsing the ELF64 executable header */
  off_t offset = 0;
  Elf64_Ehdr *eheader = mmap(NULL, ELF_EHEADER_SIZE, PROT_READ, MAP_PRIVATE, fd, offset);
  if (eheader == MAP_FAILED)
    errx(EXIT_FAILURE, "Error in Executable Header parsing !");

  /* Modifying the content of the binary to be injected following the modified variable */
  int fd_bin = open(binary, O_WRONLY);
  if (!fd_bin)
    errx(EXIT_FAILURE, "Error when opening the binary");

  int binary_size = lseek(fd_bin, 0, SEEK_END);
  if (modified)
  {
    char push = '\x68';
    write(fd_bin, &push, 1);
    write(fd_bin, &eheader->e_entry, 4);
    write(fd_bin, "\x41\x59\x41\xff\xe1", 5); /* pop r9, jmp r9 */
    binary_size += 10;

    /* Checking if there was a problem with the write opeartions */
    int new_size = lseek(fd_bin, 0, SEEK_END);
    if (new_size != binary_size)
      errx(EXIT_FAILURE, "Error when appending the jump to the entry point");
  }
  else
  {
    char ret = '\xc3';
    if (write(fd_bin, &ret, 1) == -1)
      errx(EXIT_FAILURE, "Error when writing ret into the injected binary");

    binary_size += 1;
  }
  close(fd_bin);

  /* Appending the injection code at the end of the ELF file */
  int bin = open(binary, O_RDONLY);
  if (!bin)
    errx(EXIT_FAILURE, "Cannot open the binary");

  char buffer[binary_size];
  if (read(bin, buffer, binary_size) == -1)
    errx(EXIT_FAILURE, "Error : reading the injected binary");

  close(bin);

  int elf = open(elf_file, O_WRONLY);
  if (!elf)
    errx(EXIT_FAILURE, "Cannot open the elf file");

  int off = lseek(elf, 0, SEEK_END);
  if (write(elf, buffer, binary_size) == -1)
    errx(EXIT_FAILURE, "Error when adding the injected binary at the end of the ELF file");

  close(elf);

  /* Assuring that the offset and address are congruent modulo 4096 */
  int shift = (off - base_address) % 4096;
  base_address += shift;

  /* Finding the index of the PT_NOTE program header */
  int pt_note_index = get_pt_note_index(elf_file, eheader);
  if (pt_note_index == -1)
    errx(EXIT_FAILURE, "Error with mmap when getting PT_NOTE index");

  if (pt_note_index == -2)
    errx(EXIT_FAILURE, "PT_NOTE not found");

  printf("[+] Index of PT_NOTE : %d\n", pt_note_index);

  /* Creating a section header that will replace the .note.ABI-tag section header */
  Elf64_Shdr modified_shdr;
  int note_abi_index = get_section_header_index(elf_file, eheader, ".note.ABI-tag");
  if (note_abi_index == -1)
    errx(EXIT_FAILURE, "Error when getting the index of a section header");

  else if (note_abi_index == -2)
    errx(EXIT_FAILURE, "Index of .note.ABI-tag not found");

  printf("[+] Index of .note.ABI-tag : %d\n", note_abi_index);

  off_t file_offset = create_section_header(elf_file, eheader, &modified_shdr, note_abi_index);
  if (file_offset == -1)
    errx(EXIT_FAILURE, "Error in the creation of the section header");

  modified_shdr.sh_addr = base_address;
  modified_shdr.sh_offset = off;
  modified_shdr.sh_size = binary_size;

  printf("[+] File offset to the header of .note.ABI-tag : %lx\n", file_offset);
  printf("[+] Writing the modified section header...\n");

  if (write_section_header(elf_file, file_offset, &modified_shdr, eheader) == -1)
    errx(EXIT_FAILURE, "Error : writing the modified section header");

  /* Sorting all section headers after injection */
  int move = get_closest_addresses(elf_file, eheader, &modified_shdr, note_abi_index);
  if (move == -1)
    errx(EXIT_FAILURE, "Error : getting the closest addresses");

  Elf64_Shdr sh_list[eheader->e_shnum];
  if (get_shdr_list(elf_file, eheader, sh_list) == -1)
    errx(EXIT_FAILURE, "Error when getting the section header list");

  printf("[+] Sorting all section headers...\n");
  if (sort_and_write_shdr_list(elf_file, eheader->e_shoff, eheader, sh_list, note_abi_index, move) == -1)
    errx(EXIT_FAILURE, "Error when writing the section header list");

  /* Writing the new name of the section passed in arguments */
  if (write_section_name(elf_file, section_name, eheader, &modified_shdr) == -1)
    errx(EXIT_FAILURE, "Error when writing the section name");

  /* Overwriting the PT_NOTE program header */
  printf("[+] Writing the modified PT_NOTE program header...\n");
  if (write_pt_note(elf_file, eheader, &modified_shdr, pt_note_index) == -1)
    errx(EXIT_FAILURE, "Error when writing the pt note program header");

  if (modified)
  {
    printf("[+] Overriding the executable header...\n");
    if (write_exec_header(elf_file, eheader, base_address) == 1)
      errx(EXIT_FAILURE, "Error : overriding the executable header");
  }
  else
  {
    /* Hijacking the GOT entry of a targeted function */
    int got_plt_index = get_section_header_index(elf_file, eheader, ".got.plt");
    if (got_plt_index == -1)
      errx(EXIT_FAILURE, "Error when getting the index of a section header");

    else if (got_plt_index == -2)
      errx(EXIT_FAILURE, "Index of .got.plt not found");

    printf("[+] Index of .got.plt : %d\n", got_plt_index);

    int sh_offset = get_section_header_offset(elf_file, eheader, got_plt_index);
    if (sh_offset == -1)
      errx(EXIT_FAILURE, "Error when searching for the sh_offset of .got.plt");

    /* 40 => offset in .got.plt of @getenv */
    uint64_t targeted_func = sh_offset + 40;
    if (got_hijack(elf_file, base_address, targeted_func) == -1)
      errx(EXIT_FAILURE, "Error when hijacking the GOT");
  }

  close(fd);
  munmap(eheader, ELF_EHEADER_SIZE);
  exit(EXIT_SUCCESS);
}
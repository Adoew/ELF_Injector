#include "../include/parsing.h"

#include <err.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>

int get_pt_note_index(char *filename, Elf64_Ehdr *eheader)
{
  int num_prog_hdr = eheader->e_phnum;
  size_t prog_hdr_size = num_prog_hdr * eheader->e_phnum;
  uint32_t *addr;
  int fd;

  fd = open(filename, O_RDONLY);
  if (!fd)
    return -1;

  off_t offset = 0;
  addr = mmap(NULL, prog_hdr_size, PROT_READ, MAP_PRIVATE, fd, offset);
  if (addr == MAP_FAILED)
  {
    close(fd);
    munmap(addr, prog_hdr_size);
    return -1;
  }

  /* Loop over the starting byte of each program header */
  for (int i = 0; i < num_prog_hdr; i++)
  {
    uint32_t type = addr[(eheader->e_phoff / sizeof(uint32_t)) +
                         i * (eheader->e_phentsize / sizeof(uint32_t))];
    if (type == PT_NOTE)
    {
      close(fd);
      munmap(addr, prog_hdr_size);
      return i;
    }
  }
  close(fd);
  munmap(addr, prog_hdr_size);
  return -2;
}

int get_shstrtab_index(Elf64_Ehdr *eheader)
{
  return eheader->e_shstrndx;
}

int get_section_header_index(char *filename, Elf64_Ehdr *eheader, char *section_name)
{
  int sh_start = eheader->e_shoff;
  int size = sh_start + (eheader->e_shnum * eheader->e_shentsize);
  uint8_t *addr;
  Elf64_Shdr *shdr;
  int fd;

  fd = open(filename, O_RDONLY);
  if (!fd)
    return -1;

  off_t offset = 0;
  addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset);
  if (addr == MAP_FAILED)
  {
    close(fd);
    munmap(addr, size);
    return -1;
  }

  /* Getting the offset of the .shstrtab section to get the string table */
  int shstrndx = get_shstrtab_index(eheader);
  shdr = (void *)&addr[sh_start + (shstrndx * eheader->e_shentsize)];
  int shstrtab_offset = shdr->sh_offset;

  /* Looping on the section headers to find the name in the .shstrtab section */
  for (int i = 0; i < eheader->e_shnum; i++)
  {
    shdr = (void *)&addr[sh_start + (i * eheader->e_shentsize)];
    int string_table_offset = shstrtab_offset + shdr->sh_name;
    char *string = (char *)&addr[string_table_offset];

    if (strncmp(string, section_name, strlen(section_name)) == 0)
    {
      close(fd);
      munmap(addr, size);
      return i;
    }
  }

  close(fd);
  munmap(addr, size);
  return -2;
}

int get_closest_addresses(char *filename, Elf64_Ehdr *eheader, Elf64_Shdr *sheader, int index)
{
  int sh_start = eheader->e_shoff;
  int size = sh_start + (eheader->e_shnum * eheader->e_shentsize);
  uint8_t *addr;
  Elf64_Shdr *prev_shdr;
  Elf64_Shdr *next_shdr;
  int fd;

  fd = open(filename, O_RDONLY);
  if (!fd)
    return -1;

  off_t offset = 0;
  addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset);
  if (addr == MAP_FAILED)
  {
    close(fd);
    munmap(addr, size);
    return -1;
  }

  uint64_t section_address = sheader->sh_addr;
  int index_max = eheader->e_shnum - 3;

  /* First section header => only need to check the next sh_addr */
  if (index == 1)
  {
    next_shdr = (void *)&addr[sh_start + ((index + 1) * eheader->e_shentsize)];
    if (section_address > next_shdr->sh_addr)
      return 2;
  }

  /* Last section header => only need to check the previous sh_addr */
  else if (index == index_max)
  {
    prev_shdr = (void *)&addr[sh_start + ((index - 1) * eheader->e_shentsize)];
    if (section_address < prev_shdr->sh_addr)
      return 1;
  }

  /* Default case => need to check the previous and the next sh_addr */
  else
  {
    prev_shdr = (void *)&addr[sh_start + ((index - 1) * eheader->e_shentsize)];
    next_shdr = (void *)&addr[sh_start + ((index + 1) * eheader->e_shentsize)];
    if (section_address < prev_shdr->sh_addr)
      return 1;

    else if (section_address > next_shdr->sh_addr)
      return 2;
  }

  close(fd);
  munmap(addr, size);
  return 0;
}

int get_shdr_list(char *filename, Elf64_Ehdr *eheader, Elf64_Shdr *list)
{
  int sh_start = eheader->e_shoff;
  int size = sh_start + (eheader->e_shnum * eheader->e_shentsize);
  uint8_t *addr;
  Elf64_Shdr *shdr;
  int fd;

  fd = open(filename, O_RDONLY);
  if (!fd)
    return -1;

  off_t offset = 0;
  addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset);
  if (addr == MAP_FAILED)
  {
    close(fd);
    munmap(addr, size);
    return -1;
  }

  for (int i = 0; i < eheader->e_shnum; i++)
  {
    shdr = (void *)&addr[sh_start + (i * eheader->e_shentsize)];
    list[i].sh_name = shdr->sh_name;
    list[i].sh_type = shdr->sh_type;
    list[i].sh_flags = shdr->sh_flags;
    list[i].sh_addr = shdr->sh_addr;
    list[i].sh_offset = shdr->sh_offset;
    list[i].sh_size = shdr->sh_size;
    list[i].sh_link = shdr->sh_link;
    list[i].sh_info = shdr->sh_info;
    list[i].sh_addralign = shdr->sh_addralign;
    list[i].sh_entsize = shdr->sh_entsize;
  }

  close(fd);
  munmap(addr, size);
  return 0;
}

int get_section_name_offset(char *filename, Elf64_Ehdr *eheader, Elf64_Shdr *sheader)
{
  int sh_start = eheader->e_shoff;
  int size = sh_start + (eheader->e_shnum * eheader->e_shentsize);
  uint8_t *addr;
  Elf64_Shdr *shdr;
  int fd;

  fd = open(filename, O_RDONLY);
  if (!fd)
    return -1;

  off_t offset = 0;
  addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset);
  if (addr == MAP_FAILED)
  {
    close(fd);
    munmap(addr, size);
    return -1;
  }

  /* Getting the offset of the .shstrtab section to get the string table */
  int shstrndx = eheader->e_shstrndx;
  shdr = (void *)&addr[sh_start + (shstrndx * eheader->e_shentsize)];
  int shstrtab_offset = shdr->sh_offset;

  int string_table_offset = shstrtab_offset + sheader->sh_name;
  close(fd);
  munmap(addr, size);
  return string_table_offset;
}

int get_section_header_offset(char *filename, Elf64_Ehdr *eheader, int index)
{
  int sh_start = eheader->e_shoff;
  int size = sh_start + (eheader->e_shnum * eheader->e_shentsize);
  uint8_t *addr;
  Elf64_Shdr *shdr;
  int fd;

  fd = open(filename, O_RDONLY);
  if (!fd)
    return -1;

  off_t offset = 0;
  addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset);
  if (addr == MAP_FAILED)
  {
    close(fd);
    munmap(addr, size);
    return -1;
  }

  shdr = (void *)&addr[sh_start + (index * eheader->e_shentsize)];
  int sh_offset = shdr->sh_offset;
  close(fd);
  munmap(addr, size);
  return sh_offset;
}
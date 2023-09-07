#include "../include/overwrite.h"
#include "../include/parsing.h"

#include <err.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>

int create_section_header(char *filename, Elf64_Ehdr *eheader, Elf64_Shdr *sheader, int index)
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

  /* Getting the content of the .note.ABI-tag section header to forge a modified one */
  int file_offset = sh_start + (index * eheader->e_shentsize);
  shdr = (void *)&addr[sh_start + (index * eheader->e_shentsize)];
  sheader->sh_name = shdr->sh_name;
  sheader->sh_type = SHT_PROGBITS;
  sheader->sh_flags = SHF_EXECINSTR;
  sheader->sh_link = shdr->sh_link;
  sheader->sh_info = shdr->sh_info;
  sheader->sh_addralign = 16;
  sheader->sh_entsize = shdr->sh_entsize;

  close(fd);
  munmap(addr, size);
  return file_offset;
}

int write_section_header(char *filename, off_t offset, Elf64_Shdr *sheader, Elf64_Ehdr *eheader)
{
  int fd;
  fd = open(filename, O_WRONLY);
  if (!fd)
    return -1;

  lseek(fd, offset, SEEK_SET);
  if (write(fd, sheader, eheader->e_shentsize) == -1)
    return -1;

  close(fd);
  return 0;
}

int sort_and_write_shdr_list(char *filename, int offset, Elf64_Ehdr *eheader, Elf64_Shdr *list, int index, int move)
{
  unsigned int initial = index;
  unsigned int modified = 0;
  int fd;
  fd = open(filename, O_WRONLY);
  if (!fd)
    return -1;

  if (move == 1)
  { /* Move section header to the left */
    for (int i = index; i > 1; i--)
    {
      if (list[i].sh_addr < list[i - 1].sh_addr)
      {
        Elf64_Shdr temp = list[i - 1];
        list[i - 1] = list[i];
        list[i] = temp;
        modified = i;
      }
    }
  }

  else if (move == 2)
  { /* Move section header to the right */
    for (int i = index; i < eheader->e_shnum - 3; i++)
    {
      if (list[i].sh_addr > list[i + 1].sh_addr)
      {
        Elf64_Shdr temp = list[i + 1];
        list[i + 1] = list[i];
        list[i] = temp;
        modified = i + 1;
      }
    }
  }

  /* Correcting the sh_link fields of the all section headers to avoid error with readelf */
  for (unsigned int i = 0; i < eheader->e_shnum - 3; i++)
  {
    if (list[i].sh_link <= modified && list[i].sh_link >= initial)
    {
      list[i].sh_link--;
    }
  }

  /* Rewriting the section header list */
  lseek(fd, offset, SEEK_SET);
  for (int i = 0; i < eheader->e_shnum; i++)
  {
    if (write(fd, &list[i], eheader->e_shentsize) == -1)
      return -1;
  }
  return 0;
}

int write_section_name(char *filename, char *name, Elf64_Ehdr *eheader, Elf64_Shdr *sheader)
{
  int fd;
  int offset = get_section_name_offset(filename, eheader, sheader);
  char *note_abi = ".note.ABI-tag";
  int length = strlen(note_abi);

  fd = open(filename, O_WRONLY);
  if (!fd)
    return -1;

  lseek(fd, offset, SEEK_SET);
  /* Fill the name of the section with '.' to clear the section name */
  for (int i = 0; i <= length; i++)
  {
    if (write(fd, ".", 1) == -1)
      return -1;

    lseek(fd, offset + i, SEEK_SET);
  }

  lseek(fd, offset, SEEK_SET);
  if (write(fd, name, strlen(name)) == -1)
    return -1;

  close(fd);
  return 0;
}

int write_pt_note(char *filename, Elf64_Ehdr *eheader, Elf64_Shdr *sheader, int index)
{
  int ph_start = eheader->e_phoff;
  int ph_offset = ph_start + (index * eheader->e_phentsize);
  Elf64_Phdr phdr;
  int fd;

  fd = open(filename, O_WRONLY);
  if (!fd)
    return -1;

  phdr.p_type = PT_LOAD;
  phdr.p_flags = PF_X;
  phdr.p_offset = sheader->sh_offset;
  phdr.p_vaddr = sheader->sh_addr;
  phdr.p_paddr = sheader->sh_addr;
  phdr.p_filesz = sheader->sh_size;
  phdr.p_memsz = sheader->sh_size;
  phdr.p_align = 0x1000;

  lseek(fd, ph_offset, SEEK_SET);
  if (write(fd, &phdr, eheader->e_phentsize) == -1)
    return -1;

  close(fd);
  return 0;
}

int write_exec_header(char *filename, Elf64_Ehdr *eheader, uint64_t entry)
{
  Elf64_Ehdr new_eheader;
  int fd;
  fd = open(filename, O_WRONLY);
  if (!fd)
    return -1;

  for (int i = 0; i < ELF_EHEADER_EIDENT_SIZE; i++)
  {
    new_eheader.e_ident[i] = eheader->e_ident[i];
  }

  new_eheader.e_type = eheader->e_type;
  new_eheader.e_machine = eheader->e_machine;
  new_eheader.e_version = eheader->e_version;
  new_eheader.e_entry = entry;
  new_eheader.e_phoff = eheader->e_phoff;
  new_eheader.e_shoff = eheader->e_shoff;
  new_eheader.e_flags = eheader->e_flags;
  new_eheader.e_ehsize = eheader->e_ehsize;
  new_eheader.e_phentsize = eheader->e_phentsize;
  new_eheader.e_phnum = eheader->e_phnum;
  new_eheader.e_shentsize = eheader->e_shentsize;
  new_eheader.e_shnum = eheader->e_shnum;
  new_eheader.e_shstrndx = eheader->e_shstrndx;

  if (write(fd, &new_eheader, eheader->e_phoff) == -1)
    return -1;

  close(fd);
  return 0;
}

int got_hijack(char *filename, uint64_t address, uint64_t offset)
{
  int fd = open(filename, O_WRONLY);
  if (!fd)
    return -1;

  lseek(fd, offset, SEEK_SET);
  if (write(fd, &address, 8) == -1)
    return -1;

  close(fd);
  return 0;
}
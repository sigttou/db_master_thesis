#include <stdio.h>
#include <libelf.h>
#include <fcntl.h>
#include <err.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
  int fd = open(argv[1], O_RDONLY, 0);
  if(fd < 0)
    err(EXIT_FAILURE, "open %s failed", argv[1]);
  if(elf_version(EV_CURRENT) == EV_NONE)
    errx(EXIT_FAILURE, "elf lib init failed: %s", elf_errmsg(-1));
    
  Elf* e = elf_begin(fd, ELF_C_READ, NULL);
  if(e == NULL)
    errx(EXIT_FAILURE, "elf begin failed %s", elf_errmsg(-1));
  Elf_Kind ek = elf_kind(e);

  char* k;
  switch(ek)
  {
    case ELF_K_AR:
      k = "archive";
      break;
    case ELF_K_ELF:
      k = "elf";
      break;
    case ELF_K_NONE:
      k = "data";
      break;
    default:
      k = "unknown";
  }
  printf("%s\n", k);
  elf_end(e);
}

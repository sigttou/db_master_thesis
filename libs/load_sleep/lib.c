// gcc -c -Wall -Werror -fpic lib.c
// gcc -shared -o preload.so lib.o
// rm lib.o

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

extern const char *__progname;

__attribute__((constructor)) void init(void)
{
  if(!strcmp(__progname, "msc_test"))
  {
    size_t i = 0;
    while(i++ < 6000000000);
  }

    //raise(SIGTSTP);
}

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

extern const char *__progname;

__attribute__((constructor)) void init(void)
{
  //if(!strcmp(__progname, "sudo"))
  if(strstr(__progname, "2msc"))
  {
    size_t i = 0;
    while(i++ < 4000000000);
  }

    //raise(SIGTSTP);
}

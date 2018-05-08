#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

extern const char *__progname;

__attribute__((constructor)) void init(void)
{
  //if(!strcmp(__progname, "sudo"))
  if(strstr(__progname, "2msc"))
    sleep(5);
    //raise(SIGTSTP);
}

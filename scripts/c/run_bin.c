#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <libelf.h>

extern char** environ;
extern int errno;

typedef struct
{
  char* name_;
  int fd_;
}my_shminfo;

void rand_str(char *dest, size_t length);
my_shminfo rand_shm(void);
void check_exit(char cond, char* error, int val);
void load_bin(char* path, int shm_fd);
void exec_shm(char* shm_name, char** params);

int main(int argc, char** argv)
{
  my_shminfo shm = rand_shm();
  int shm_fd = shm.fd_;
  load_bin(argv[1], shm_fd);
  close(shm_fd);
  exec_shm(shm.name_, &argv[1]);
  shm_unlink(shm.name_);
  return 0;
}

my_shminfo rand_shm(void)
{
  my_shminfo info;
  size_t len = 10;
  char* filename = malloc(len);
  rand_str(filename, len);
  int shm = shm_open(filename, O_RDWR|O_CREAT|O_EXCL, 0777);
  while(shm == -1)
  {
    rand_str(filename, len);
    shm = shm_open(filename, O_RDWR|O_CREAT|O_EXCL, 0777);
  }
  info.name_ = filename;
  info.fd_ = shm;
  return info;
}

void rand_str(char *dest, size_t length)
{
  /*https://stackoverflow.com/a/15768317*/
  char charset[] = "0123456789"
                   "abcdefghijklmnopqrstuvwxyz"
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  while (length-- > 0)
  {
    size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
    *dest++ = charset[index];
  }
  *dest = '\0';
}

void check_exit(char cond, char* error, int val)
{
  if(!cond)
    return;
  printf("%s\n", error);
  exit(val);
}

void load_bin(char* path, int shm_fd)
{
  struct stat st;
  int rc = stat(path, &st);
  check_exit((rc == -1), "stat failed", 2);

  rc = ftruncate(shm_fd, st.st_size);
  check_exit((rc == -1), strerror(errno), 3);

  void* p = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, shm_fd, 0);
  check_exit((p == MAP_FAILED), "mmap failed", 4);

  int fd = open(path, O_RDONLY);
  check_exit((fd == -1), "open failed", 5);

  rc = read(fd, p, st.st_size);
  check_exit((rc == -1), "read failed", 6);
  check_exit((rc != st.st_size), "read failed invalid size", 7);
  munmap(p, st.st_size);
}

void exec_shm(char* shm_name, char** params)
{
  int shm_fd = shm_open(shm_name, O_RDONLY, 0);
  if(fork())
    fexecve(shm_fd, params, environ);
  close(shm_fd);
  wait(NULL);
}

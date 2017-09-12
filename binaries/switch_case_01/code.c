#include <stdio.h>

int main(int argc, char** argv)
{
    int x;
    if(argc > 1)
      sscanf(argv[1], "%d", &x);
    switch(x)
    {
      case 1:
        printf("failure\n");
        break;
      case 2:
        printf("success\n");
        break;
      case 3:
        printf("what are you doing\n");
        break;
      case 4:
        printf("no no no\n");
        break;
      default:
        printf("Give a number between 1 and 4\n");
        break;
    }
    return 0;
}

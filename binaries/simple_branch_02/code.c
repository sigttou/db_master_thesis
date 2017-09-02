#include <stdio.h>

int main(int argc, char** argv)
{
    printf("Hello!\n");
    int x;
    if(argc > 1)
      sscanf(argv[1], "%d", &x);
    if(2 == x)
        printf("search.\n");
    else
        printf("nope.\n");
    return 0;
}

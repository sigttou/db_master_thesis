#include <stdio.h>

int main(int argc, char** argv)
{
    printf("Hello!\n");
    int x;
    if(argc > 1)
      sscanf(argv[1], "%d", &x);
    if(2 == x)
        printf("success.\n");
    else
        printf("failure.\n");
    return 0;
}

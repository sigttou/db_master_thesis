#include <stdio.h>

int main(int argc, char** argv)
{
    int x,y;
    if(argc > 1)
      sscanf(argv[1], "%d", &x);
    if(argc > 2)
      sscanf(argv[2], "%d", &y);
    if(2 == x)
        printf("success.\n");
    else
        printf("failure.\n");
    if(y == 2)
        printf("success.\n");
    else
        printf("failure.\n");
    return 0;
}

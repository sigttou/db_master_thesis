#include <stdio.h>

char glob = 10;

int main(void)
{
    if(glob == 11)
        printf("success.\n");
    else
        printf("fail.\n");
    return 0;
}

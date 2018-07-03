#include <stdio.h>

extern char getsucc(void);

int main(void)
{
    if(getsucc())
        printf("success.\n");
    else
        printf("fail.\n");
    return 0;
}

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
using namespace std;
typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;
int main(int argc, char *argv[])
{
    int txt_file, img_file;
    uint width, height, i;
    ulong txt_size;
    uchar *txt_data, *img_data;
    /* Test the number of parameters received */
    if (argc != 3)
    {
        fprintf(stderr, "usage: %s text_file bmp_image\n", argv[0]);
        return -1;
    }
    if ((txt_file = open(argv[1], O_RDONLY)) < 0)
    {
        perror(argv[0]);
        return -2;
    }
    if ((img_file = open(argv[2], O_RDWR)) < 0)
    {
        perror(argv[0]);
        return -3;
    }
    
    
    return 0;
}

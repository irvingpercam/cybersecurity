#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#define END 240

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;

int main(int argc, char* argv[]) {
  int txt_file, img_file;
  uint width, height, i;
  ulong txt_size;
  uchar *txt_data, *img_data;

  if (argc != 3) {
      fprintf(stderr, "usage: %s txt_file bmp_file\n", argv[0]);
      return -1;
  }

  if ( (txt_file = open(argv[1], O_RDONLY)) < 0 ) {
    perror(argv[0]);
    return -2;
  }

  if ( (img_file = open(argv[2], O_RDWR)) < 0 ) {
    perror(argv[0]);
    return -3;
  }

  lseek(img_file, 18, SEEK_SET);
  read(img_file, &width, sizeof(uint));
  read(img_file, &height, sizeof(uint));

  txt_size = lseek(txt_file, 0, SEEK_END);
  lseek(txt_file, 0, SEEK_SET);
  if (txt_size > (width * height)) {
    printf("%s: The size of the text must be less than the number of pixels\n", argv[0]);
    return -4;
  }

  txt_data = (uchar*) malloc(sizeof(uchar) * txt_size);
  if (txt_data == NULL) {
  	printf("%s: No memory space for TXT\n", argv[0]);
  	return -5;
  }
  read(txt_file, txt_data, sizeof(uchar) * txt_size);

  img_data = (uchar*) malloc(sizeof(uchar) * width * height * 3);
  if (img_data == NULL) {
  	printf("%s: No memory space for IMG\n", argv[0]);
  	return -5;
  }
  lseek(img_file, 54, SEEK_SET);
  read(img_file, img_data, sizeof(uchar) * width * height * 3);

  for (i = 0; i < txt_size; i++) {
  	img_data[i * 3] = txt_data[i];
  }
  img_data[i * 3] = END;

  lseek(img_file, 54, SEEK_SET);
  write(img_file, img_data, sizeof(uchar) * width * height * 3);

  free(txt_data);
  free(img_data);
  close(txt_file);
  close(img_file);
  return 0;
}
/*
*
* Curso: Seguridad informática
* Equipo:
*           Irving Alain Aguilar Pérez - A01703171
*           Javier Méndez Martínez - A01703446
*           Jorge Lopez - A01209043
* Fecha: Lunes, 16 de Marzo de 2020.
* Título: Implementación de algoritmo AES
* Descripción:
*   Para encriptar un mensaje, proporcionamos un mensaje y una llave.
*   Posteriormente, el programa actúa sobre el mensaje y devuelve información irreconocible.
*
*   Para desencriptar un mensaje, únicamente se siguen las instrucciones de la encriptación,
*   pero a la inversa.
*
*   Las llaves en AES pueden ser de 128 bits, 192 bits o 256 bits (El algoritmo original de
*   Rijndael también permite llaves de 160 y 224 bits).
*
*   El tamaño de la llave determina en número de ciclos de operaciones sobre la matriz de estado.
*   Entre mayor sea el tamaño de una llave, más ciclos de operaciones se realizarán, siendo esto
*   más seguro en teoría, pero a su vez, más lento en cuanto a tiempo de encriptación.
*
*   Cada ciclo utiliza una versión modificada de la llave original. Lo anterior se conoce como
*   "AES Key Expansion". Este proceso altera la llave, de manera que sea distinta para cada uno
*   de los ciclos. Viéndolo desde otro punto, este proceso encripta la llave por sí misma.
*   
*
*/
/* [START] LIBRARIES */
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
/* [END] LIBRARIES */
using namespace std;
// Tabla de Rijndael, obtenida de: https://cryptography.fandom.com/wiki/Rijndael_S-box
unsigned char s_box[256] =  
 {0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76
 ,0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0
 ,0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15
 ,0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75
 ,0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84
 ,0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf
 ,0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8
 ,0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2
 ,0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73
 ,0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb
 ,0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79
 ,0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08
 ,0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a
 ,0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e
 ,0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf
 ,0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16
 };
// LOOKUP TABLES
unsigned char mul2[] = {
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
    0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
    0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
    0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
    0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
    0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
    0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
    0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
    0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
    0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
    0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
    0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
    0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
    0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
    0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
    0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};
unsigned char mul3[] = {
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
    0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
    0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
    0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
    0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
    0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
    0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
    0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
    0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
    0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
    0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
    0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
    0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
    0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
    0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
    0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
};
unsigned char rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};
unsigned char inv_s_box[256] =  
 {
  0X52, 0X09, 0X6A, 0XD5, 0X30, 0X36, 0XA5, 0X38, 0XBF, 0X40, 0XA3, 0X9E, 0X81, 0XF3, 0XD7, 0XFB,
  0X7C, 0XE3, 0X39, 0X82, 0X9B, 0X2F, 0XFF, 0X87, 0X34, 0X8E, 0X43, 0X44, 0XC4, 0XDE, 0XE9, 0XCB,
  0X54, 0X7B, 0X94, 0X32, 0XA6, 0XC2, 0X23, 0X3D, 0XEE, 0X4C, 0X95, 0X0B, 0X42, 0XFA, 0XC3, 0X4E,
  0X08, 0X2E, 0XA1, 0X66, 0X28, 0XD9, 0X24, 0XB2, 0X76, 0X5B, 0XA2, 0X49, 0X6D, 0X8B, 0XD1, 0X25,
  0X72, 0XF8, 0XF6, 0X64, 0X86, 0X68, 0X98, 0X16, 0XD4, 0XA4, 0X5C, 0XCC, 0X5D, 0X65, 0XB6, 0X92,
  0X6C, 0X70, 0X48, 0X50, 0XFD, 0XED, 0XB9, 0XDA, 0X5E, 0X15, 0X46, 0X57, 0XA7, 0X8D, 0X9D, 0X84,
  0X90, 0XD8, 0XAB, 0X00, 0X8C, 0XBC, 0XD3, 0X0A, 0XF7, 0XE4, 0X58, 0X05, 0XB8, 0XB3, 0X45, 0X06,
  0XD0, 0X2C, 0X1E, 0X8F, 0XCA, 0X3F, 0X0F, 0X02, 0XC1, 0XAF, 0XBD, 0X03, 0X01, 0X13, 0X8A, 0X6B,
  0X3A, 0X91, 0X11, 0X41, 0X4F, 0X67, 0XDC, 0XEA, 0X97, 0XF2, 0XCF, 0XCE, 0XF0, 0XB4, 0XE6, 0X73,
  0X96, 0XAC, 0X74, 0X22, 0XE7, 0XAD, 0X35, 0X85, 0XE2, 0XF9, 0X37, 0XE8, 0X1C, 0X75, 0XDF, 0X6E,
  0X47, 0XF1, 0X1A, 0X71, 0X1D, 0X29, 0XC5, 0X89, 0X6F, 0XB7, 0X62, 0X0E, 0XAA, 0X18, 0XBE, 0X1B,
  0XFC, 0X56, 0X3E, 0X4B, 0XC6, 0XD2, 0X79, 0X20, 0X9A, 0XDB, 0XC0, 0XFE, 0X78, 0XCD, 0X5A, 0XF4,
  0X1F, 0XDD, 0XA8, 0X33, 0X88, 0X07, 0XC7, 0X31, 0XB1, 0X12, 0X10, 0X59, 0X27, 0X80, 0XEC, 0X5F,
  0X60, 0X51, 0X7F, 0XA9, 0X19, 0XB5, 0X4A, 0X0D, 0X2D, 0XE5, 0X7A, 0X9F, 0X93, 0XC9, 0X9C, 0XEF,
  0XA0, 0XE0, 0X3B, 0X4D, 0XAE, 0X2A, 0XF5, 0XB0, 0XC8, 0XEB, 0XBB, 0X3C, 0X83, 0X53, 0X99, 0X61,
  0X17, 0X2B, 0X04, 0X7E, 0XBA, 0X77, 0XD6, 0X26, 0XE1, 0X69, 0X14, 0X63, 0X55, 0X21, 0X0C, 0X7D
 };
// LOOKUP TABLES
// GF(256) 9x multiplication lookup table used for inv_mix_columns operation
unsigned char mul9[256] = {
  0X00,0X09,0X12,0X1B,0X24,0X2D,0X36,0X3F,0X48,0X41,0X5A,0X53,0X6C,0X65,0X7E,0X77,
  0X90,0X99,0X82,0X8B,0XB4,0XBD,0XA6,0XAF,0XD8,0XD1,0XCA,0XC3,0XFC,0XF5,0XEE,0XE7,
  0X3B,0X32,0X29,0X20,0X1F,0X16,0X0D,0X04,0X73,0X7A,0X61,0X68,0X57,0X5E,0X45,0X4C,
  0XAB,0XA2,0XB9,0XB0,0X8F,0X86,0X9D,0X94,0XE3,0XEA,0XF1,0XF8,0XC7,0XCE,0XD5,0XDC,
  0X76,0X7F,0X64,0X6D,0X52,0X5B,0X40,0X49,0X3E,0X37,0X2C,0X25,0X1A,0X13,0X08,0X01,
  0XE6,0XEF,0XF4,0XFD,0XC2,0XCB,0XD0,0XD9,0XAE,0XA7,0XBC,0XB5,0X8A,0X83,0X98,0X91,
  0X4D,0X44,0X5F,0X56,0X69,0X60,0X7B,0X72,0X05,0X0C,0X17,0X1E,0X21,0X28,0X33,0X3A,
  0XDD,0XD4,0XCF,0XC6,0XF9,0XF0,0XEB,0XE2,0X95,0X9C,0X87,0X8E,0XB1,0XB8,0XA3,0XAA,
  0XEC,0XE5,0XFE,0XF7,0XC8,0XC1,0XDA,0XD3,0XA4,0XAD,0XB6,0XBF,0X80,0X89,0X92,0X9B,
  0X7C,0X75,0X6E,0X67,0X58,0X51,0X4A,0X43,0X34,0X3D,0X26,0X2F,0X10,0X19,0X02,0X0B,
  0XD7,0XDE,0XC5,0XCC,0XF3,0XFA,0XE1,0XE8,0X9F,0X96,0X8D,0X84,0XBB,0XB2,0XA9,0XA0,
  0X47,0X4E,0X55,0X5C,0X63,0X6A,0X71,0X78,0X0F,0X06,0X1D,0X14,0X2B,0X22,0X39,0X30,
  0X9A,0X93,0X88,0X81,0XBE,0XB7,0XAC,0XA5,0XD2,0XDB,0XC0,0XC9,0XF6,0XFF,0XE4,0XED,
  0X0A,0X03,0X18,0X11,0X2E,0X27,0X3C,0X35,0X42,0X4B,0X50,0X59,0X66,0X6F,0X74,0X7D,
  0XA1,0XA8,0XB3,0XBA,0X85,0X8C,0X97,0X9E,0XE9,0XE0,0XFB,0XF2,0XCD,0XC4,0XDF,0XD6,
  0X31,0X38,0X23,0X2A,0X15,0X1C,0X07,0X0E,0X79,0X70,0X6B,0X62,0X5D,0X54,0X4F,0X46
};
// GF(256) 11x multiplication lookup table used for inv_mix_columns operation
unsigned char mul11[256] = {
  0X00,0X0B,0X16,0X1D,0X2C,0X27,0X3A,0X31,0X58,0X53,0X4E,0X45,0X74,0X7F,0X62,0X69,
  0XB0,0XBB,0XA6,0XAD,0X9C,0X97,0X8A,0X81,0XE8,0XE3,0XFE,0XF5,0XC4,0XCF,0XD2,0XD9,
  0X7B,0X70,0X6D,0X66,0X57,0X5C,0X41,0X4A,0X23,0X28,0X35,0X3E,0X0F,0X04,0X19,0X12,
  0XCB,0XC0,0XDD,0XD6,0XE7,0XEC,0XF1,0XFA,0X93,0X98,0X85,0X8E,0XBF,0XB4,0XA9,0XA2,
  0XF6,0XFD,0XE0,0XEB,0XDA,0XD1,0XCC,0XC7,0XAE,0XA5,0XB8,0XB3,0X82,0X89,0X94,0X9F,
  0X46,0X4D,0X50,0X5B,0X6A,0X61,0X7C,0X77,0X1E,0X15,0X08,0X03,0X32,0X39,0X24,0X2F,
  0X8D,0X86,0X9B,0X90,0XA1,0XAA,0XB7,0XBC,0XD5,0XDE,0XC3,0XC8,0XF9,0XF2,0XEF,0XE4,
  0X3D,0X36,0X2B,0X20,0X11,0X1A,0X07,0X0C,0X65,0X6E,0X73,0X78,0X49,0X42,0X5F,0X54,
  0XF7,0XFC,0XE1,0XEA,0XDB,0XD0,0XCD,0XC6,0XAF,0XA4,0XB9,0XB2,0X83,0X88,0X95,0X9E,
  0X47,0X4C,0X51,0X5A,0X6B,0X60,0X7D,0X76,0X1F,0X14,0X09,0X02,0X33,0X38,0X25,0X2E,
  0X8C,0X87,0X9A,0X91,0XA0,0XAB,0XB6,0XBD,0XD4,0XDF,0XC2,0XC9,0XF8,0XF3,0XEE,0XE5,
  0X3C,0X37,0X2A,0X21,0X10,0X1B,0X06,0X0D,0X64,0X6F,0X72,0X79,0X48,0X43,0X5E,0X55,
  0X01,0X0A,0X17,0X1C,0X2D,0X26,0X3B,0X30,0X59,0X52,0X4F,0X44,0X75,0X7E,0X63,0X68,
  0XB1,0XBA,0XA7,0XAC,0X9D,0X96,0X8B,0X80,0XE9,0XE2,0XFF,0XF4,0XC5,0XCE,0XD3,0XD8,
  0X7A,0X71,0X6C,0X67,0X56,0X5D,0X40,0X4B,0X22,0X29,0X34,0X3F,0X0E,0X05,0X18,0X13,
  0XCA,0XC1,0XDC,0XD7,0XE6,0XED,0XF0,0XFB,0X92,0X99,0X84,0X8F,0XBE,0XB5,0XA8,0XA3
};
// GF(256) 13x multiplication lookup table used for inv_mix_columns operation
unsigned char mul13[256] = {
  0X00,0X0D,0X1A,0X17,0X34,0X39,0X2E,0X23,0X68,0X65,0X72,0X7F,0X5C,0X51,0X46,0X4B,
  0XD0,0XDD,0XCA,0XC7,0XE4,0XE9,0XFE,0XF3,0XB8,0XB5,0XA2,0XAF,0X8C,0X81,0X96,0X9B,
  0XBB,0XB6,0XA1,0XAC,0X8F,0X82,0X95,0X98,0XD3,0XDE,0XC9,0XC4,0XE7,0XEA,0XFD,0XF0,
  0X6B,0X66,0X71,0X7C,0X5F,0X52,0X45,0X48,0X03,0X0E,0X19,0X14,0X37,0X3A,0X2D,0X20,
  0X6D,0X60,0X77,0X7A,0X59,0X54,0X43,0X4E,0X05,0X08,0X1F,0X12,0X31,0X3C,0X2B,0X26,
  0XBD,0XB0,0XA7,0XAA,0X89,0X84,0X93,0X9E,0XD5,0XD8,0XCF,0XC2,0XE1,0XEC,0XFB,0XF6,
  0XD6,0XDB,0XCC,0XC1,0XE2,0XEF,0XF8,0XF5,0XBE,0XB3,0XA4,0XA9,0X8A,0X87,0X90,0X9D,
  0X06,0X0B,0X1C,0X11,0X32,0X3F,0X28,0X25,0X6E,0X63,0X74,0X79,0X5A,0X57,0X40,0X4D,
  0XDA,0XD7,0XC0,0XCD,0XEE,0XE3,0XF4,0XF9,0XB2,0XBF,0XA8,0XA5,0X86,0X8B,0X9C,0X91,
  0X0A,0X07,0X10,0X1D,0X3E,0X33,0X24,0X29,0X62,0X6F,0X78,0X75,0X56,0X5B,0X4C,0X41,
  0X61,0X6C,0X7B,0X76,0X55,0X58,0X4F,0X42,0X09,0X04,0X13,0X1E,0X3D,0X30,0X27,0X2A,
  0XB1,0XBC,0XAB,0XA6,0X85,0X88,0X9F,0X92,0XD9,0XD4,0XC3,0XCE,0XED,0XE0,0XF7,0XFA,
  0XB7,0XBA,0XAD,0XA0,0X83,0X8E,0X99,0X94,0XDF,0XD2,0XC5,0XC8,0XEB,0XE6,0XF1,0XFC,
  0X67,0X6A,0X7D,0X70,0X53,0X5E,0X49,0X44,0X0F,0X02,0X15,0X18,0X3B,0X36,0X21,0X2C,
  0X0C,0X01,0X16,0X1B,0X38,0X35,0X22,0X2F,0X64,0X69,0X7E,0X73,0X50,0X5D,0X4A,0X47,
  0XDC,0XD1,0XC6,0XCB,0XE8,0XE5,0XF2,0XFF,0XB4,0XB9,0XAE,0XA3,0X80,0X8D,0X9A,0X97
};
// GF(256) 14x multiplication lookup table used for inv_mix_columns operation
unsigned char mul14[256] = {
  0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
  0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
  0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
  0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
  0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
  0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
  0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
  0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
  0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
  0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
  0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
  0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
  0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
  0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
  0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
  0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d
};
/* [START] FUNCTIONS */
/* [START] KEYEXPANSION 
*   Esta función toma una llave de 128 bits y la expande, de tal manera que se tenga una nueva
*   llave para cada ciclo. Cada una de las llaves es de 16 bytes. Se necesita un total de 176
*   bytes; 16 bytes para cada uno de los 10 ciclos y 16 adicionales para la llave original.
*
*   El núcleo de este algoritmo es una serie de 3 pasos. El núcleo toma un bloque de 4 bytes de las
*   llaver generadas (se realiza una operación XOR con los 4 bytes generados por el núcleo), y
*   se procede a realizar las siguientes operaciones:
*   1. Rotación
*   2. Caja de Rijndael
*   3. Rcon - Rijndael Key Schedule
*/
void keyExpansionCore(unsigned char* in, unsigned char i){
    // Rotación a la izquierda
    unsigned int* q = (unsigned int*)in;
    *q = (*q >> 8) | ((*q & 0xff) << 24);
    // Caja de Rijndael con 4 bytes
    in[0] = s_box[in[0]]; in[1] = s_box[in[1]];
    in[2] = s_box[in[2]]; in[3] = s_box[in[3]];
    // Rcon - Rijndael Key Schedule
    in[0] ^= rcon[i];
}
// Copiar la llave original de 128 bits en los primeros 16 bits de la llave expandida.
void keyExpansion(unsigned char* inputKey, unsigned char* expandedKeys){
    for (int i = 0; i < 16; i++)
    {
        expandedKeys[i] = inputKey[i];
    }
    int bytesGenerated = 16;
    int rconIteration = 1;
    unsigned char temp[4];
    while (bytesGenerated < 176)
    {
        // Leer 4 bytes del nucleo
        for (int i = 0; i < 4; i++)
        {
            temp[i] = expandedKeys[i + bytesGenerated - 4];
        }
        // Llamar a función core por cada llave de 16 bytes.
        if (bytesGenerated % 16 == 0)
        {
            keyExpansionCore(temp, rconIteration++);
        }
        // Guardar operación XOR en expandedKeys
        for (unsigned char a = 0; a < 4; a++)
        {
            expandedKeys[bytesGenerated] = expandedKeys[bytesGenerated - 16] ^ temp[a];
            bytesGenerated++;
        }
        
    }
    
}
/* [START] SUBBYTES
*   Esta función reemplaza cada byte del esado por otro byte, dependiendo de la llave recibida
*   como parámetro. Las sustituciones son presentadas en una tabla, generalmente conocida como
*   caja de Rijndael. Esta tabla consiste en sustituciones de 256 bytes contenidas en un arreglo
*   de 16x16.
*/
void subBytes(unsigned char* state){
    for (int i = 0; i < 16; i++)
    {
        state[i] = s_box[state[i]];
    }
}
void inv_sub_bytes(unsigned char* state) {
  // Substitute each state value with another byte in the Rijndael S-Box
  for (int i = 0; i < 16; i++)
    state[i] = inv_s_box[state[i]];
}
/* [START] SHIFTROWS
*   Esta función recorre las filas del estado hacia la izquierda.
*   La primera fila no se recorre.
*   La segunda fila se recorre 1 byte a la izquierda.
*   La tercera fila se recorre 2 bytes, y la última fila se recorre 3 bytes.
*   De manera que los bits se van recorriendo hacia la izquierda, estos reaparecen en la parte
*   derecha. Esta operación es conocida comúnmente como rotación. --> DIFUSIÓN
*/
void shiftRows(unsigned char* state){
    unsigned char tmp[16];
    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];

    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];

    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
    
}
void inv_shift_rows(unsigned char* state) {
  unsigned char tmp[16];

  // First row don't shift (idx = idx)
  tmp[0] = state[0];
  tmp[4] = state[4];
  tmp[8] = state[8];
  tmp[12] = state[12];

  // Second row shift right once (idx = (idx - 4) % 16)
  tmp[1] = state[13];
  tmp[5] = state[1];
  tmp[9] = state[5];
  tmp[13] = state[9];

  // Third row shift right twice (idx = (idx +/- 8) % 16)
  tmp[2] = state[10];
  tmp[6] = state[14];
  tmp[10] = state[2];
  tmp[14] = state[6];

  // Fourth row shift right three times (idx = (idx + 4) % 16)
  tmp[3] = state[7];
  tmp[7] = state[11];
  tmp[11] = state[15];
  tmp[15] = state[3];

  for (int i = 0; i < 16; i++)
     state[i] = tmp[i];
}
/* [START] MIXCOLUMNS 
*   Esta función sirve para calcular el producto punto entre los arreglos binarios.
*   Posterior al producto punto, los resultados se suman y se reducen para que puedan entrar
*   en un byte (véase MOD(a,b,c,d,...,n)). Al final, el se realiza una operación XOR entre resultados.
*/
void mixColumns(unsigned char* state){
    unsigned char tmp[16];

    tmp[0] = (unsigned char)(mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
    tmp[1] = (unsigned char)(state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
    tmp[2] = (unsigned char)(state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
    tmp[3] = (unsigned char)(mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);

    tmp[4] = (unsigned char)(mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
    tmp[5] = (unsigned char)(state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
    tmp[6] = (unsigned char)(state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
    tmp[7] = (unsigned char)(mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);

    tmp[8] = (unsigned char)(mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
    tmp[9] = (unsigned char)(state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
    tmp[10] = (unsigned char)(state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
    tmp[11] = (unsigned char)(mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);

    tmp[12] = (unsigned char)(mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
    tmp[13] = (unsigned char)(state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
    tmp[14] = (unsigned char)(state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
    tmp[15] = (unsigned char)(mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);

    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
    
}
void inv_mix_columns(unsigned char* state) {
  unsigned char tmp[16];

  // Column 1
  tmp[0] = (unsigned char) (mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]]);
  tmp[1] = (unsigned char) (mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]]);
  tmp[2] = (unsigned char) (mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]]);
  tmp[3] = (unsigned char) (mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]]);
 
  // Column 2
  tmp[4] = (unsigned char) (mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]]);
  tmp[5] = (unsigned char) (mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]]);
  tmp[6] = (unsigned char) (mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]]);
  tmp[7] = (unsigned char) (mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]]);
 
  // Column 3
  tmp[8] = (unsigned char) (mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]]);
  tmp[9] = (unsigned char) (mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]]);
  tmp[10] = (unsigned char) (mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]]);
  tmp[11] = (unsigned char) (mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]]);
 
  // Column 4
  tmp[12] = (unsigned char) (mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]]);
  tmp[13] = (unsigned char) (mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]]);
  tmp[14] = (unsigned char) (mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]]);
  tmp[15] = (unsigned char) (mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]]);

  for (int i = 0; i < 16; i++)
     state[i] = tmp[i];
}
/* [START] ADDROUNDKEY 
*   Esta función es utilizada para realizar una suma entre el estado y la llave del ciclo
*   utilizando operaciones de aritmética (suma binaria mod 2). Esto significa que cada bit
*   en el input es sumado al bit correspondiente en la llave del ciclo, guardando el mod 2
*   del resultado en el estado. --> XOR
*/
void addRoundKey(unsigned char* state, unsigned char* roundKey){
    for (int i = 0; i < 16; i++)
    {
        state[i] ^= roundKey[i];
    }
}
void aes_encrypt(unsigned char* message, unsigned char* key){
    unsigned char state[16];
    for (int i = 0; i < 16; i++)
    {
        state[i] = message[i];
    }
    int rounds = 9;
    unsigned char expandedKey[176];
    keyExpansion(key, expandedKey);
    addRoundKey(state, expandedKey);
    for (int i = 0; i < rounds; i++)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expandedKey + (16 * (i+1)));
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expandedKey + 160);
    // Copiar estado encriptado al mensaje
    for (int i = 0; i < 16; i++)
    {
        message[i] = state[i];
    }
    
}
void aes_decrypt(unsigned char* message, unsigned char* key){
    unsigned char state[16];
    for (int i = 0; i < 16; i++)
    {
        state[i] = message[i];
    }
    int rounds = 9;
    unsigned char expandedKey[176];
    keyExpansion(key, expandedKey);
    addRoundKey(state, expandedKey+160);
    for (int i = rounds; i > 0; i--)
    {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        addRoundKey(state, expandedKey + (16 * i));
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    addRoundKey(state, expandedKey);
    // Copiar estado encriptado al mensaje
    for (int i = 0; i < 16; i++)
    {
        message[i] = state[i];
    }
    
}
/* [START] PRINTHEXADECIMAL */
void printHexadecimal(unsigned char a){
    if(a / 16 < 10){
        cout<<(char)((a / 16) + '0');
    }
    if(a / 16 >= 10){
        cout<<(char)((a / 16 -10) + 'A');
    }
    if(a % 16 < 10){
        cout<<(char)((a % 16) + '0');
    }
    if(a % 16 >= 10){
        cout<<(char)((a % 16 -10) + 'A');
    }
}
/* [END] FUNCTIONS */
/* [START] MAIN FUNCTION */
int main(){
    int opcion;
    char mensaje[] = "This is a message we will encrypt with AES!";
    unsigned char mensaje_enc[] = {
        0XB6, 0X4B, 0X27, 0XBB, 0X16, 0X15, 0XA6, 0XF5, 0X32, 0X18, 0X6C, 0XC5, 0XFA, 0X94, 0XB5, 0X5E,
        0X5C, 0X54, 0XEA, 0X1B, 0XDF, 0X97, 0X1E, 0X3D, 0XE3, 0X1B, 0XFC, 0X02, 0X75, 0X22, 0X76, 0X52,
        0XD5, 0X7B, 0XD5, 0X42, 0XBA, 0X0F, 0X68, 0X50, 0XCD, 0XFD, 0X59, 0XB8, 0XEB, 0X0E, 0X83, 0XD1
    };
    // Para esta implementación, estaremos utilizando una llave de 16 bytes.
    unsigned char key[16];
    
    do {

        int originalLength = strlen((const char*)mensaje);
        int lengthPMessage = originalLength;
        
        // Revisar si el mensaje cabe en 16 bytes
        if (lengthPMessage % 16 != 0)
        {
            lengthPMessage = (lengthPMessage / 16 + 1) * 16;
        }
        unsigned char * pMessage = new unsigned char[lengthPMessage];
        for (int i = 0; i < lengthPMessage; i++)
        {
            if (i >= originalLength)
            {
                pMessage[i] = 0;
            }
            else
            {
                pMessage[i] = mensaje[i];
            }
        }

        cout<< "\nQue deseas realizar"<<endl;
        cout<< "1. Encriptar"<<endl;
        cout<< "2. Desencriptar"<<endl;
        cout<< "3. Salir"<<endl;
        cin >> opcion;
        switch (opcion)
        {
        case 1:
            cin.ignore(256, '\n');
            // Mensaje a encriptar.
            cout<<"Mensaje a encriptar: ";
            cin.getline(mensaje, 100);
            cout<<endl;
            cout<<"Llave para encriptar: ";
            for (int i = 0; i < 16; i++)
            {
                scanf("%hhu", &key[i]);
            }

            // Encriptar mensaje
            for (int i = 0; i < lengthPMessage; i+=16)
            {
                aes_encrypt(pMessage+i, key);
            }
            // Imprimir mensaje encriptado
            cout <<"Mensaje encriptado: "<<endl;
            for (int i = 0; i < lengthPMessage; i++)
            {
                cout<<"0x";
                printHexadecimal(pMessage[i]);
                cout<<" ";
            }
            cout<<endl;
            break;
        case 2:
            // Desencriptar mensaje
            cout<<"Llave para encriptar: ";
            for (int i = 0; i < 16; i++)
            {
                scanf("%hhu", &key[i]);
            }
            for (int i = 0; i < lengthPMessage; i+=16)
            {
                aes_decrypt(pMessage+i, key);
            }
            // Imprimir mensaje desencriptado
            cout <<"Mensaje desencriptado: "<<endl;
            cout << mensaje<<endl;
            break;
        delete[] pMessage;
        }
    }while(opcion!=3);
    cout<<endl<<endl;
    return 0;
}
/* [END] MAIN FUNCTION */
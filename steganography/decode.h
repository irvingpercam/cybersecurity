/* AES ENCODE LIBRARY */
#ifndef DECODE_H
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
#include <cstring>
#include <fstream>
#include <sstream>
#include "rijndael.h"

using namespace std;
/* [START] SUBBYTES
*   Esta función reemplaza cada byte del esado por otro byte, dependiendo de la llave recibida
*   como parámetro. Las sustituciones son presentadas en una tabla, generalmente conocida como
*   caja de Rijndael. Esta tabla consiste en sustituciones de 256 bytes contenidas en un arreglo
*   de 16x16.
*/
void subBytes(unsigned char * state)
{
	for (int i = 0; i < 16; i++)
    {
		state[i] = inv_s[state[i]];
	}
}
/* [START] SHIFTROWS
*   Esta función recorre las filas del estado hacia la izquierda.
*   La primera fila no se recorre.
*   La segunda fila se recorre 1 byte a la izquierda.
*   La tercera fila se recorre 2 bytes, y la última fila se recorre 3 bytes.
*   De manera que los bits se van recorriendo hacia la izquierda, estos reaparecen en la parte
*   derecha. Esta operación es conocida comúnmente como rotación. --> DIFUSIÓN
*/
void shiftRows(unsigned char * state)
{
	unsigned char tmp[16];

	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

	for (int i = 0; i < 16; i++)
    {
		state[i] = tmp[i];
	}
}
/* [START] MIXCOLUMNS 
*   Esta función sirve para calcular el producto punto entre los arreglos binarios.
*   Posterior al producto punto, los resultados se suman y se reducen para que puedan entrar
*   en un byte (véase MOD(a,b,c,d,...,n)). Al final, el se realiza una operación XOR entre resultados.
*/
void inverseMixColumns(unsigned char * state)
{
	unsigned char tmp[16];

	tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
	tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
	tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
	tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

	tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
	tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
	tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
	tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

	tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
	tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
	tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
	tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

	tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
	tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
	tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
	tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}
/* [START] ADDROUNDKEY 
*   Esta función es utilizada para realizar una suma entre el estado y la llave del ciclo
*   utilizando operaciones de aritmética (suma binaria mod 2). Esto significa que cada bit
*   en el input es sumado al bit correspondiente en la llave del ciclo, guardando el mod 2
*   del resultado en el estado. --> XOR
*/
void addRoundKey(unsigned char * state, unsigned char * roundKey)
{
	for (int i = 0; i < 16; i++)
    {
		state[i] ^= roundKey[i];
	}
}

void aes_decrypt(unsigned char * encryptedMessage, unsigned char * key, unsigned char * decryptedMessage)
{
	unsigned char state[16];
	for (int i = 0; i < 16; i++)
    {
		state[i] = encryptedMessage[i];
	}
    addRoundKey(state, key+160);
	shiftRows(state);
	subBytes(state);
	int numberOfRounds = 9;
	for (int i = 8; i >= 0; i--)
    {
        addRoundKey(state, key + (16 * (i + 1)));
        inverseMixColumns(state);
        shiftRows(state);
        subBytes(state);
	}
	addRoundKey(state, key);
	for (int i = 0; i < 16; i++)
    {
		decryptedMessage[i] = state[i];
	}
}
#define DECODE_H
#endif /*AES_H*/
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
#include "structures.h"

using namespace std;
/* [START] SUBBYTES
*   Esta función reemplaza cada byte del esado por otro byte, dependiendo de la llave recibida
*   como parámetro. Las sustituciones son presentadas en una tabla, generalmente conocida como
*   caja de Rijndael. Esta tabla consiste en sustituciones de 256 bytes contenidas en un arreglo
*   de 16x16.
*/
void SubBytes(unsigned char * state)
{
	for (int i = 0; i < 16; i++)
    {
		state[i] = inv_s[state[i]];
	}
}
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
    unsigned char expandedKey[176];
	keyExpansion(key, expandedKey);
    addRoundKey(state, expandedKey+160);
	shiftRows(state);
	SubBytes(state);
	int numberOfRounds = 9;
	for (int i = 8; i >= 0; i--)
    {
        addRoundKey(state, expandedKey + (16 * (i + 1)));
        inverseMixColumns(state);
        shiftRows(state);
        SubBytes(state);
	}
	addRoundKey(state, expandedKey);
	for (int i = 0; i < 16; i++)
    {
		decryptedMessage[i] = state[i];
	}
}
int main(int argc, char* argv[]) {
	string mensaje; // Variable para almacenar el mensaje
	ifstream topsecret; // Archivo de entrada
	topsecret.open("topsecret.aes", ios::in | ios::binary); // Leer el archivo
	if (topsecret.is_open())
	{
		getline(topsecret, mensaje);
        cout<<"Leyendo archivo..."<<endl;
		topsecret.close();
	}
	else
    {
        fprintf(stderr, "%s: fallo al abrir el archivo del mensaje\n", argv[0]); // Error de archivo de entrada
    }
	char * msg = new char[mensaje.size()+1];
	strcpy(msg, mensaje.c_str()); // Copiar el mensaje a msg
	int messageLength = strlen((const char*)msg);
	unsigned char * encryptedMessage = new unsigned char[messageLength];
	for (int i = 0; i < messageLength; i++) {
		encryptedMessage[i] = (unsigned char)msg[i];
	}
    // Liberar memoria
	delete[] msg;
	unsigned char key[16];
    cout<<"Clave privada: ";
    for (int i = 0; i < 16; i++)
    {
        scanf("%hhu", &key[i]);
    }
	int messageLen = strlen((const char *)encryptedMessage);
	unsigned char * decryptedMessage = new unsigned char[messageLen];
	for (int i = 0; i < messageLen; i += 16) {
		aes_decrypt(encryptedMessage + i, key, decryptedMessage + i);
	}
	cout << "Mensaje descifrado en hexadecimal: " << endl;
	for (int i = 0; i < messageLen; i++) {
        if (decryptedMessage[i] != '\0')
        {
            cout << hex << (int)decryptedMessage[i];
		    cout << " ";
        }
        else
        {
            break;
        }
	}
	cout << endl;
	cout << "Mensaje descifrado: ";
	for (int i = 0; i < messageLen; i++) {
        if (decryptedMessage[i] != '\0')
        {
            cout<<decryptedMessage[i];
        }
        else
        {
            break;
        }
	}
	cout << endl;
	return 0;
}
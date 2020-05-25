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
#include <stdlib.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include "structures.h"
/* [END] LIBRARIES */
using namespace std;
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
    addRoundKey(state, key);
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
/* [START] PRINTHEXADECIMAL */
void printHexadecimal(unsigned char a, int i, unsigned char * encryptedMessage){
    if(a / 16 < 10){
        encryptedMessage[i] =(char)((a / 16) + '0');
        cout<<encryptedMessage[i];
    }
    if(a / 16 >= 10){
        encryptedMessage[i] = (char)((a / 16 -10) + 'A');
        cout<<encryptedMessage[i];
    }
    if(a % 16 < 10){
        encryptedMessage[i] = (char)((a % 16) + '0');
        cout<<encryptedMessage[i];
    }
    if(a % 16 >= 10){
        encryptedMessage[i] = (char)((a % 16 -10) + 'A');
        cout<<encryptedMessage[i];
    }
}
/* [END] FUNCTIONS */
/* [START] MAIN FUNCTION */
int main(){
    // Mensaje a encriptar.
    cout<<"Mensaje a encriptar: ";
    char mensaje[1024];
    cin.getline(mensaje, sizeof(mensaje));
    cout<<endl;
    // Para esta implementación, estaremos utilizando una llave de 16 bytes.
    unsigned char key[16];
    cout<<"Llave privada: ";
    for (int i = 0; i < 16; i++)
    {
        scanf("%hhu", &key[i]);
    }
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
    unsigned char * encryptedMessage = new unsigned char[lengthPMessage];
    // Encriptar mensaje
    for (int i = 0; i < lengthPMessage; i+=16)
    {
        aes_encrypt(pMessage+i, key);
    }
    // Imprimir mensaje encriptado
    cout<<endl;
    cout <<"Mensaje cifrado en hexadecimal: "<<endl;
    for (int i = 0; i < lengthPMessage; i++)
    {
        printHexadecimal(pMessage[i], i, encryptedMessage);
        cout<<" ";
    }
    cout<<endl<<endl;
    // Write file with encrypted message
    ofstream outfile;
    outfile.open("topsecret.aes", ios::out | ios::binary);
    if (outfile.is_open())
    {
        outfile<<pMessage;
        outfile.close();
        cout<<"Operación exitosa: Archivo topsecret.aes creado"<<endl;
    }
    else
    {
        cout<<"Operación fallida: El archivo topsecret.aes no fue creado"<<endl;
    }
    delete[] pMessage;
    delete[] encryptedMessage;
    return 0;
}
/* [END] MAIN FUNCTION */
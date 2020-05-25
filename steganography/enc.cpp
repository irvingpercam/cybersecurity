#include "encode.h"
/* [START] MAIN FUNCTION */
int main(){
    // Mensaje a encriptar.
    cout<<"Mensaje a cifrar: ";
    char mensaje[1024];
    cin.getline(mensaje, sizeof(mensaje));
    cout<<endl;
    // Para esta implementación, estaremos utilizando una llave de 16 bytes.
    unsigned char key[16];
    cout<<"Clave privada a 16 dígitos: ";
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
#include "decode.h"
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
    cout<<"Clave privada a 16 dígitos: ";
    for (int i = 0; i < 16; i++)
    {
        scanf("%hhu", &key[i]);
    }
	unsigned char expandedKey[176];
	keyExpansion(key, expandedKey);
	int messageLen = strlen((const char *)encryptedMessage);
	unsigned char * decryptedMessage = new unsigned char[messageLen];
	for (int i = 0; i < messageLen; i += 16) {
		aes_decrypt(encryptedMessage + i, expandedKey, decryptedMessage + i);
	}
	cout << "Mensaje descifrado en hexadecimal: "<< endl;
	for (int i = 0; i < messageLen; i++) {
        if (decryptedMessage[i] != '\0')
        {
            cout <<hex<< (int)decryptedMessage[i];
		    cout << " ";
        }
        else
        {
            break;
        }
	}
	cout<<endl<<endl;
	cout<<"Mensaje descifrado: ";
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
	cout<<endl;
	return 0;
}
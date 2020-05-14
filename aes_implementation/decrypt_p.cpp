#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>
#include <dirent.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
using namespace std;
string Decrypt_string(char *Key, string HEX_Message, int size)
{
    static const char* const lut = "0123456789ABCDEF";
    int i = 0;
    char* Res;
    AES_KEY dec_key;
    string auxString, output, newString;

    for(i = 0; i < size; i += 2)
    {
        string byte = HEX_Message.substr(i, 2);
        char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        auxString.push_back(chr);
    }

    const char *Msg = auxString.c_str();
    Res = (char *)malloc(size);

    AES_set_decrypt_key((unsigned char *)Key, 128, &dec_key);

    for(i = 0; i <= size; i += 16)
    {
        AES_ecb_encrypt((unsigned char *)Msg + i, (unsigned char *)Res + i, &dec_key, AES_DECRYPT);
    }

    output.reserve(2 * size);

    for (size_t i = 0; i < size; ++i)
    {
        const unsigned char c = Res[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }

    int len = output.length();

    for(int i = 0; i < len; i += 2)
    {
        string byte = output.substr(i, 2);
        char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        newString.push_back(chr);
    }

    free(Res);

    return newString;
}
int main(){

    return 0;
}
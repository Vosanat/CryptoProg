#include <iostream>
#include <fstream>
#include <iomanip>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
using namespace CryptoPP;

int main()
{
    std::ifstream file("text.txt");
    CryptoPP::SHA256 hash;
    byte digest[CryptoPP::SHA256::DIGESTSIZE];
    FileSource(file, true,  new HashFilter(hash, new CryptoPP::HexEncoder(new ArraySink(digest, CryptoPP::SHA256::DIGESTSIZE))));
    std::cout << "Hash: ";
    for (int i = 0; i < CryptoPP::SHA256::DIGESTSIZE; ++i) {
        std::cout << digest[i];
    }
    std::cout << std::endl;

    return 0;
}

#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/des.h>

#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

void encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    try {
        // Generate random Key (secret)
        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::byte key[CryptoPP::DES::DEFAULT_KEYLENGTH];
        prng.GenerateBlock(key, sizeof(key));

        // Save Key to key_file in hex format
        std::string keyHex;
        CryptoPP::StringSource(key, sizeof(key), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(keyHex)));
        std::ofstream keyFile("key_file.txt");
        keyFile << keyHex;
        keyFile.close();

        // Generate random IV (not secret)
        CryptoPP::byte iv[CryptoPP::DES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));

        // Save IV to iv_file in hex format
        std::string ivHex;
        CryptoPP::StringSource(iv, sizeof(iv), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(ivHex)));
        std::ofstream ivFile("iv_file.txt");
        ivFile << ivHex;
        ivFile.close();

        // Encryption
        CryptoPP::CBC_Mode<CryptoPP::DES>::Encryption encr;
        encr.SetKeyWithIV(key, sizeof(key), iv);

        CryptoPP::FileSource(inputFile.c_str(), true, new CryptoPP::StreamTransformationFilter(encr,new CryptoPP::HexEncoder( new CryptoPP::FileSink(outputFile.c_str()))));

        std::cout << "Файл " << inputFile << " зашифрован и сохранен в " << outputFile << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}

void decryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    try {
        // Read Key from key_file
        std::ifstream keyFile("key_file.txt");
        std::string keyHex((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());
        keyFile.close();

        // Convert Key from hex to byte format
        std::string key;
        CryptoPP::StringSource(keyHex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(key)));

        // Read IV from iv_file
        std::ifstream ivFile("iv_file.txt");
        std::string ivHex((std::istreambuf_iterator<char>(ivFile)), std::istreambuf_iterator<char>());
        ivFile.close();

        // Convert IV from hex to byte format
        std::string iv;
        CryptoPP::StringSource(ivHex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(iv)));

        // Decryption
        CryptoPP::CBC_Mode<CryptoPP::DES>::Decryption decr;
        decr.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size(), reinterpret_cast<const CryptoPP::byte*>(iv.data()));

        CryptoPP::FileSource(inputFile.c_str(), true, new CryptoPP::HexDecoder( new CryptoPP::StreamTransformationFilter(decr,  new CryptoPP::FileSink((outputFile.c_str())))));

        std::cout << "Файл " << inputFile << " расшифрован и сохранен в " << outputFile << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}

bool fileExists(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary);
    return file.good();
}

int main()
{
    try {
        std::cout << "====================================================================" << std::endl;
        std::cout << "Привет, это программа зашифрования/расшифрования содержимого файлов." << std::endl;
        std::cout << "====================================================================" << std::endl;
        std::cout << "Желаете, продолжить? (y - да, n - нет): ";
        char mode2;
        std::cin >> mode2;
        if (mode2 == 'y') {
            while (true) {
                std::cout << "--------------------------------------------------------------------" << std::endl;
                std::cout << "Для завершения работы программы, введите 0." << std::endl;
                std::cout << "Выберите режим работы (e - зашифрование, d - расшифрование): ";
                char mode1;
                std::cin >> mode1;
                if (mode1 == '0') {
                    std::cout << "Желаете, завершить? (y - да, n - нет): ";
                    char mode;
                    std::cin >> mode;
                    if (mode == 'y') {
                        return 0;
                    }
                }
                if (mode1 == 'e' || mode1 == 'd') {
                    std::string inputFile, outputFile, password;
                    std::cout << "Введите путь к файлу ввода: ";
                    std::cin >> inputFile;
                    std::cout << "Введите путь к файлу вывода: ";
                    std::cin >> outputFile;
                    std::cout << "Введите пароль: ";
                    std::cin >> password;

                    if (!fileExists(inputFile)) {
                        std::cout << "Файл для ввода не существует. Будьте внимательнее!" << std::endl;
                        continue;
                    }

                    std::ofstream outFile(outputFile);
                    if (!outFile) {
                        std::cout << "Не удалось открыть файл для записи результата." << std::endl;
                        continue;
                    }

                    if (mode1 == 'e') {
                        encryptFile(inputFile, outputFile, password);
                        std::cout << "Файл успешно зашифрован." << std::endl;
                    } else if (mode1 == 'd') {
                        decryptFile(inputFile, outputFile, password);
                        std::cout << "Файл успешно расшифрован." << std::endl;
                    }

                    outFile.close();
                } else {
                    std::cout << "Неверный режим работы." << std::endl;
                }
            }
        } else {
            return 0;
        }
    } catch (CryptoPP::InvalidArgument& e) {
        std::cerr << "Ошибка: неверный аргумент." << std::endl;
        return 1;
    }
}

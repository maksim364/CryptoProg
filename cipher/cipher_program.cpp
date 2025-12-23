#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>  

using namespace CryptoPP;

void encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    AutoSeededRandomPool prng;
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];

    PKCS5_PBKDF2_HMAC<SHA256> kdf;
    kdf.DeriveKey(key, sizeof(key), 0, (byte*)password.data(), password.size(), NULL, 0, 1000);
    prng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);

    if (!in || !out) {
        throw std::runtime_error("Ошибка открытия файлов");
    }

    out.write(reinterpret_cast<char*>(iv), sizeof(iv));

    FileSource(in, true, new StreamTransformationFilter(encryptor, new FileSink(out)));
}

void decryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];

    PKCS5_PBKDF2_HMAC<SHA256> kdf;
    kdf.DeriveKey(key, sizeof(key), 0, (byte*)password.data(), password.size(), NULL, 0, 1000);

    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);

    if (!in || !out) {
        throw std::runtime_error("Ошибка открытия файлов");
    }

    in.read(reinterpret_cast<char*>(iv), sizeof(iv));

    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    FileSource(in, true, new StreamTransformationFilter(decryptor, new FileSink(out)));
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Использование: " << argv[0] << " <encrypt|decrypt> <входной файл> <выходной файл> <пароль>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string password = argv[4];

    try {
        if (mode == "encrypt") {
            encryptFile(inputFile, outputFile, password);
            std::cout << "Файл зашифрован: " << outputFile << std::endl;
        } else if (mode == "decrypt") {
            decryptFile(inputFile, outputFile, password);
            std::cout << "Файл расшифрован: " << outputFile << std::endl;
        } else {
            std::cerr << "Неверный режим. Используйте 'encrypt' или 'decrypt'." << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

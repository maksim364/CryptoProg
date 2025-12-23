#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Использование: " << argv[0] << " <имя файла>" << std::endl;
        return 1;
    }

    std::string filename = argv[1];
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Ошибка: не удалось открыть файл " << filename << std::endl;
        return 1;
    }

    SHA256 hash;
    std::string digest;
    FileSource(file, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    std::cout << "SHA-256 хеш файла '" << filename << "':" << std::endl;
    std::cout << digest << std::endl;

    return 0;
}

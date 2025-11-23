#pragma once

#include <iostream>
#include <vector>
#include <cstdint>

class Encryptor {
public:
    static const unsigned int CIPHER_BLOCK_SIZE = 16; 

    Encryptor(const std::string& password);

    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext, bool useSalt = true);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext);
private:
    std::string password;

};
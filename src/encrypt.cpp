#include "encrypt.h"
#include <openssl/evp.h>
#include <string>
#include <openssl/rand.h>
#include "s3fs_logger.h"
using std::string;


Encryptor::Encryptor(const std::string& pwd) : password(pwd) {}

std::vector<uint8_t> Encryptor::Encrypt(const std::vector<uint8_t> &plaintext, bool useSalt)
{
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char salt[8];

    if (useSalt) {
        if (RAND_bytes(salt, 8) != 1) {
            S3FS_PRN_ERR("Error generating salt");
        }
    }

    // derives key and iv based on salt and password
    if(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), useSalt ? salt : nullptr, reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1, key, iv) == 0) {
        S3FS_PRN_ERR("Error storing salt and iv");
    }

    // create cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        S3FS_PRN_ERR("Error creating cipher context");
    }

    // initialize cipher context
    const EVP_CIPHER *type = EVP_aes_256_cbc();

    if (EVP_EncryptInit_ex(ctx, type, NULL, key, iv) == 0) {
        EVP_CIPHER_CTX_free(ctx);
        S3FS_PRN_ERR("Error initializing cipher context");
    };

    //create output vector
    std::vector<uint8_t> encrypted_data(plaintext.size() + CIPHER_BLOCK_SIZE);
    int first_length_filled = 0;

    // encrypt data
    if (EVP_EncryptUpdate(ctx, encrypted_data.data(), &first_length_filled, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) == 0) {
        EVP_CIPHER_CTX_free(ctx);
        S3FS_PRN_ERR("Error encrypting data");
    }

    int second_length_filled = 0;

    if (EVP_EncryptFinal_ex(ctx, encrypted_data.data(), &second_length_filled) == 0) {
        EVP_CIPHER_CTX_free(ctx);
        S3FS_PRN_ERR("Error encrypting final piece of data");
    }

    encrypted_data.resize(first_length_filled + second_length_filled);

    std::vector<uint8_t> final_data;

    if (useSalt) {
        final_data.resize(16 + encrypted_data.size());

        const char salted_prefix[8] = { 'S','a','l','t','e','d','_','_' };

        std::copy(salted_prefix, salted_prefix + 8, final_data.begin());
        std::copy(salt, salt + 8, final_data.begin() + 8);
        std::copy(encrypted_data.begin(), encrypted_data.end(), final_data.begin() + 16);

    } else {
        final_data = encrypted_data;
    }

    EVP_CIPHER_CTX_free(ctx);

    return final_data;

}

std::vector<uint8_t> Encryptor::Decrypt(const std::vector<uint8_t> &ciphertext)
{
    return {};
}
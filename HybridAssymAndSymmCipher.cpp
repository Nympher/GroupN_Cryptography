#include <iostream>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>

// Generate an RSA key pair (for Person A and B)
RSA* generate_RSA_key_pair(int bits) {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, bits, bn, nullptr);
    BN_free(bn);
    return rsa;
}

// Encrypt a message with AES
void AES_encrypt_decrypt(const std::string &input, unsigned char *key) {
    // Initialization Vector (IV)
    unsigned char iv[AES_BLOCK_SIZE] = {0x00};  // All zeros IV for simplicity

    // Encrypt using AES
    AES_KEY encryptKey;
    AES_set_encrypt_key(key, 128, &encryptKey);

    unsigned char enc_out[input.size() + 1];
    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(input.c_str()),
                    enc_out, input.size(),
                    &encryptKey, iv, AES_ENCRYPT);

    std::cout << "Encrypted Text (hex): ";
    for (int i = 0; i < input.size(); i++) {
        printf("%02x", enc_out[i]);
    }
    std::cout << std::endl;

    // Decrypt using AES
    unsigned char dec_out[input.size() + 1];
    AES_KEY decryptKey;
    AES_set_decrypt_key(key, 128, &decryptKey);

    std::memcpy(iv, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", AES_BLOCK_SIZE); // Reset IV for decryption
    AES_cbc_encrypt(enc_out, dec_out, input.size(), &decryptKey, iv, AES_DECRYPT);

    std::cout << "Decrypted Text: ";
    for (int i = 0; i < input.size(); i++) {
        std::cout << dec_out[i];
    }
    std::cout << std::endl;
}

// Encrypt AES Key with RSA (for sending the secret key securely)
std::string RSA_encrypt_AES_key(RSA* rsa, unsigned char *aes_key) {
    int rsa_len = RSA_size(rsa);
    unsigned char* encrypted_key = new unsigned char[rsa_len];
    RSA_public_encrypt(16, aes_key, encrypted_key, rsa, RSA_PKCS1_PADDING);

    std::string encrypted_key_str(reinterpret_cast<char*>(encrypted_key), rsa_len);
    delete[] encrypted_key;
    return encrypted_key_str;
}

// Decrypt AES Key with RSA (for receiving the secret key securely)
void RSA_decrypt_AES_key(RSA* rsa, const std::string &encrypted_key, unsigned char *aes_key) {
    int rsa_len = RSA_size(rsa);
    unsigned char* decrypted_key = new unsigned char[rsa_len];

    RSA_private_decrypt(rsa_len, reinterpret_cast<const unsigned char*>(encrypted_key.c_str()),
                        decrypted_key, rsa, RSA_PKCS1_PADDING);

    std::memcpy(aes_key, decrypted_key, 16); // 16-byte AES key
    delete[] decrypted_key;
}

int main() {
    // Step 1: Generate RSA Key pair (for Person B's public key and private key)
    RSA* rsa = generate_RSA_key_pair(2048);

    // Step 2: Person A generates AES key (for symmetric encryption)
    unsigned char aes_key[AES_BLOCK_SIZE];
    RAND_bytes(aes_key, AES_BLOCK_SIZE);  // Generate random AES key for encryption

    std::cout << "AES Key: ";
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", aes_key[i]);
    }
    std::cout << std::endl;

    // Step 3: Encrypt AES key using Person B's RSA public key (RSA encryption)
    std::string encrypted_aes_key = RSA_encrypt_AES_key(rsa, aes_key);
    std::cout << "Encrypted AES Key (hex): ";
    for (char c : encrypted_aes_key) {
        printf("%02x", static_cast<unsigned char>(c));
    }
    std::cout << std::endl;

    // Step 4: Person A sends the encrypted AES key to Person B
    // (In this example, we are just simulating by passing the encrypted key directly)

    // Step 5: Person B decrypts the AES key using their RSA private key
    unsigned char decrypted_aes_key[AES_BLOCK_SIZE];
    RSA_decrypt_AES_key(rsa, encrypted_aes_key, decrypted_aes_key);

    std::cout << "Decrypted AES Key (Person B): ";
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", decrypted_aes_key[i]);
    }
    std::cout << std::endl;

    // Step 6: Person A and Person B use the decrypted AES key to encrypt/decrypt messages
    std::string plainText = "This is a secret message.";

    std::cout << "\nOriginal Message: " << plainText << std::endl;
    AES_encrypt_decrypt(plainText, decrypted_aes_key);

    RSA_free(rsa); // Free RSA resources
    return 0;
}

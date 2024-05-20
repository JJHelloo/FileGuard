#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

std::vector<unsigned char> deriveKey(const std::string &password, const std::vector<unsigned char> &salt)
{
    const int key_length = 32; // 256 bits for AES-256
    std::vector<unsigned char> key(key_length);

    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), 10000, EVP_sha256(), key_length, key.data()))
    {
        handleErrors();
    }

    return key;
}

void encryptFile(const std::string &filePath, const std::string &password)
{
    // Generate salt
    std::vector<unsigned char> salt(16);
    if (!RAND_bytes(salt.data(), salt.size()))
    {
        handleErrors();
    }

    // Derive key
    std::vector<unsigned char> key = deriveKey(password, salt);

    // Load the cipher
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    if (!cipher)
    {
        std::cerr << "Error loading cipher" << std::endl;
        return;
    }

    // Create and initialize the encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        std::cerr << "Error creating context" << std::endl;
        return;
    }

    // Generate IV
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (!RAND_bytes(iv, sizeof(iv)))
    {
        handleErrors();
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key.data(), iv) != 1)
    {
        handleErrors();
    }

    // Read the input file in binary mode
    std::ifstream in(filePath, std::ios::binary);
    if (!in)
    {
        std::cerr << "Error opening input file" << std::endl;
        return;
    }

    std::vector<unsigned char> inputFileData((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Encrypt the file content
    std::vector<unsigned char> outbuf(inputFileData.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen;
    if (EVP_EncryptUpdate(ctx, outbuf.data(), &outlen, inputFileData.data(), inputFileData.size()) != 1)
    {
        handleErrors();
    }

    int templen;
    if (EVP_EncryptFinal_ex(ctx, outbuf.data() + outlen, &templen) != 1)
    {
        handleErrors();
    }
    outlen += templen;

    // Write salt, IV, and encrypted content back to the input file in binary mode
    std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        std::cerr << "Error opening input file for writing" << std::endl;
        return;
    }

    out.write((char *)salt.data(), salt.size());
    out.write((char *)iv, sizeof(iv));
    out.write((char *)outbuf.data(), outlen);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Encryption completed." << std::endl;
}

void decryptFile(const std::string &filePath, const std::string &password)
{
    // Open the input file in binary mode
    std::ifstream in(filePath, std::ios::binary);
    if (!in)
    {
        std::cerr << "Error opening input file" << std::endl;
        return;
    }

    // Read salt and IV from the input file
    std::vector<unsigned char> salt(16);
    in.read((char *)salt.data(), salt.size());
    if (in.gcount() != salt.size())
    {
        std::cerr << "Error reading salt from input file" << std::endl;
        return;
    }

    unsigned char iv[EVP_MAX_IV_LENGTH];
    in.read((char *)iv, sizeof(iv));
    if (in.gcount() != sizeof(iv))
    {
        std::cerr << "Error reading IV from input file" << std::endl;
        return;
    }

    // Read the remaining encrypted data from the file
    std::vector<unsigned char> encryptedData((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Derive key
    std::vector<unsigned char> key = deriveKey(password, salt);

    // Load the cipher
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    if (!cipher)
    {
        std::cerr << "Error loading cipher" << std::endl;
        return;
    }

    // Create and initialize the decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        std::cerr << "Error creating context" << std::endl;
        return;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key.data(), iv) != 1)
    {
        handleErrors();
    }

    // Decrypt the file content
    std::vector<unsigned char> outbuf(encryptedData.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen;
    if (EVP_DecryptUpdate(ctx, outbuf.data(), &outlen, encryptedData.data(), encryptedData.size()) != 1)
    {
        handleErrors();
    }

    int templen;
    if (EVP_DecryptFinal_ex(ctx, outbuf.data() + outlen, &templen) != 1)
    {
        handleErrors();
    }
    outlen += templen;

    // Write decrypted content back to the input file in binary mode
    std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        std::cerr << "Error opening input file for writing" << std::endl;
        return;
    }

    out.write((char *)outbuf.data(), outlen);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Decryption completed." << std::endl;
}

int main()
{
    std::string filePath, password;
    char choice;

    std::cout << "Enter 'e' to encrypt or 'd' to decrypt: ";
    std::cin >> choice;
    std::cin.ignore(); // Ignore newline character after choice input

    std::cout << "Enter the file path: ";
    std::getline(std::cin, filePath);

    std::cout << "Enter the password: ";
    std::getline(std::cin, password);

    if (choice == 'e')
    {
        // Encrypt file
        encryptFile(filePath, password);
    }
    else if (choice == 'd')
    {
        // Decrypt file
        decryptFile(filePath, password);
    }
    else
    {
        std::cerr << "Invalid choice! Please enter 'e' to encrypt or 'd' to decrypt." << std::endl;
    }

    return 0;
}

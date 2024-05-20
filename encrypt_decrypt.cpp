#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm> // for std::fill
#include <cstring>   // for std::strlen

// Include the filesystem library with a fallback for different environments
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::__fs::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#elif __has_include(<__fs::filesystem>)
#include <__fs::filesystem>
namespace fs = std::__fs::filesystem;
#else
#error "No filesystem support"
#endif

// Handle OpenSSL errors by printing them to stderr and aborting the program
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// Derive a key from the password and salt using PBKDF2 with HMAC-SHA-256
std::vector<unsigned char> deriveKey(const std::string &password, const std::vector<unsigned char> &salt)
{
    const int key_length = 32; // 256 bits for AES-256
    std::vector<unsigned char> key(key_length);

    // Generate key using PBKDF2 with HMAC-SHA-256
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), 10000, EVP_sha256(), key_length, key.data()))
    {
        handleErrors();
    }

    return key;
}

// Encrypt the file at the given path with the given password
void encryptFile(const std::string &filePath, const std::string &password)
{
    // Check if the file exists
    if (!fs::exists(filePath))
    {
        std::cerr << "Error: File does not exist: " << filePath << std::endl;
        return;
    }

    // Check if the password is empty
    if (password.empty())
    {
        std::cerr << "Error: Password cannot be empty." << std::endl;
        return;
    }

    // Generate salt (32 bytes for enhanced security)
    std::vector<unsigned char> salt(32);
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

    // Read file content into a vector
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

    // Clear sensitive data from memory
    std::fill(key.begin(), key.end(), 0);
    std::fill(inputFileData.begin(), inputFileData.end(), 0);
    std::fill(outbuf.begin(), outbuf.end(), 0);

    std::cout << "Encryption completed." << std::endl;
}

// Decrypt the file at the given path with the given password
void decryptFile(const std::string &filePath, const std::string &password)
{
    // Check if the file exists
    if (!fs::exists(filePath))
    {
        std::cerr << "Error: File does not exist: " << filePath << std::endl;
        return;
    }

    // Check if the password is empty
    if (password.empty())
    {
        std::cerr << "Error: Password cannot be empty." << std::endl;
        return;
    }

    // Open the input file in binary mode
    std::ifstream in(filePath, std::ios::binary);
    if (!in)
    {
        std::cerr << "Error opening input file" << std::endl;
        return;
    }

    // Read salt and IV from the input file
    std::vector<unsigned char> salt(32); // Use 32 bytes salt for decryption as well
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

    // Clear sensitive data from memory
    std::fill(key.begin(), key.end(), 0);
    std::fill(encryptedData.begin(), encryptedData.end(), 0);
    std::fill(outbuf.begin(), outbuf.end(), 0);

    std::cout << "Decryption completed." << std::endl;
}

int main()
{
    std::string filePath, password;
    char choice;

    // Prompt user for action: encrypt or decrypt
    std::cout << "Enter 'e' to encrypt or 'd' to decrypt: ";
    std::cin >> choice;
    std::cin.ignore(); // Ignore newline character after choice input

    // Prompt user for file path
    std::cout << "Enter the file path: ";
    std::getline(std::cin, filePath);

    // Prompt user for password
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

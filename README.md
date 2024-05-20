**File Encryption and Decryption**
This program allows you to encrypt and decrypt files using AES-256-CBC encryption. It leverages the OpenSSL library for cryptographic operations.

**Features**
Encrypts a file using a password-based key derivation function (PBKDF2 with HMAC-SHA-256).
Decrypts an encrypted file using the same password.
Securely handles encryption and decryption with salt and initialization vector (IV).

Requirements
OpenSSL library

C++ compiler
Installation
OpenSSL Installation

On Ubuntu/Debian
sudo apt-get update
sudo apt-get install libssl-dev

On macOS
Copy code
brew install openssl
Compiling the Program
Save the source code to a file, e.g., file_encrypt_decrypt.cpp.
Compile the program using a C++ compiler, linking the OpenSSL library:

g++ -o file_encrypt_decrypt file_encrypt_decrypt.cpp -lssl -lcrypto

Run the compiled program:
./file_encrypt_decrypt
Follow the prompts to choose between encryption and decryption:

Enter e to encrypt a file.
Enter d to decrypt a file.
Provide the file path and password when prompted.

Example
Enter 'e' to encrypt or 'd' to decrypt: e
Enter the file path: /path/to/your/file.txt
Enter the password: yourpassword

Program Flow
The program reads the user's choice (encrypt or decrypt).
It reads the file path and password.
Depending on the choice:

For encryption:
Generates a salt and an IV.
Derives a key from the password and salt using PBKDF2.
Encrypts the file content using AES-256-CBC.
Writes the salt, IV, and encrypted content back to the file.

For decryption:
Reads the salt and IV from the file.
Derives a key from the password and salt using PBKDF2.
Decrypts the file content using AES-256-CBC.
Writes the decrypted content back to the file.

Error Handling
The program uses the handleErrors() function to print OpenSSL errors and abort execution in case of failures.

Dependencies
The program includes the following OpenSSL headers:
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

Important Notes
Ensure the OpenSSL library is correctly installed and linked during compilation.
Use a strong and unique password for encryption to ensure the security of your files.

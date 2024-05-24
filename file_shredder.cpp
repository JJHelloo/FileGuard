#include <iostream>
#include <fstream>
#include <random>
#include <filesystem>
#include <string>

void secureDelete(const std::string &filename, int passes)
{
    // Check if the file exists
    if (!std::filesystem::exists(filename))
    {
        std::cerr << "File does not exist: " << filename << std::endl;
        return;
    }

    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }

    // Get file size
    std::streamsize size = file.tellg();
    file.close();

    // Determine buffer size based on file size
    std::size_t bufferSize = size < 4096 ? static_cast<std::size_t>(size) : 4096;

    // Initialize random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    // Overwrite the file multiple times
    std::vector<char> buffer(bufferSize);
    for (int pass = 0; pass < passes; ++pass)
    {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open())
        {
            std::cerr << "Failed to open file for writing: " << filename << std::endl;
            return;
        }

        for (std::streamsize i = 0; i < size; i += buffer.size())
        {
            for (auto &byte : buffer)
            {
                byte = static_cast<char>(dis(gen));
            }
            file.write(buffer.data(), std::min(static_cast<std::streamsize>(buffer.size()), size - i));
            // Optionally, print progress
            std::cout << "\rOverwriting... " << (i + buffer.size()) * 100 / size << "%" << std::flush;
        }

        file.close();
        std::cout << "\nPass " << pass + 1 << "/" << passes << " complete." << std::endl;
    }

    // Confirm deletion
    char confirm;
    std::cout << "Are you sure you want to delete the file? (y/n): ";
    std::cin >> confirm;
    if (confirm == 'y' || confirm == 'Y')
    {
        // Delete the file
        if (std::filesystem::remove(filename))
        {
            std::cout << "File securely deleted: " << filename << std::endl;
        }
        else
        {
            std::cerr << "Failed to delete file: " << filename << std::endl;
        }
    }
    else
    {
        std::cout << "File deletion canceled." << std::endl;
    }
}

int main()
{
    std::string filename;
    int passes;

    std::cout << "Enter the file name to securely delete: ";
    std::cin >> filename;

    std::cout << "Enter the number of passes: ";
    std::cin >> passes;

    secureDelete(filename, passes);

    return 0;
}

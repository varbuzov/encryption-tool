#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

namespace fs = std::filesystem;
const std::string VERIFICATION_TAG = "MYXOR";

enum class CipherType {
    XOR,
    REVERSE
};

fs::path getExecutablePath() {
#ifdef _WIN32
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return fs::path(buffer);
#else
    char result[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
    return fs::path(std::string(result, (count > 0) ? count : 0));
#endif
}

std::string generateRandomKey(size_t length = 16) {
    const std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::default_random_engine rng(static_cast<unsigned>(time(nullptr)));
    std::uniform_int_distribution<size_t> dist(0, charset.size() - 1);

    std::string key;
    for (size_t i = 0; i < length; ++i)
        key += charset[dist(rng)];
    return key;
}

void xorEncryptDecrypt(std::vector<char>& data, const std::string& key) {
    for (size_t i = 0; i < data.size(); ++i)
        data[i] ^= key[i % key.size()];
}

void reverseEncryptDecrypt(std::vector<char>& data) {
    std::reverse(data.begin(), data.end());
}

void applyEncryption(std::vector<char>& data, const std::string& key, CipherType cipher) {
    if (cipher == CipherType::XOR)
        xorEncryptDecrypt(data, key);
    else if (cipher == CipherType::REVERSE)
        reverseEncryptDecrypt(data);
}

bool shouldEncryptFile(const fs::path& path, const std::string& extension, bool allFiles) {
    if (!path.has_extension()) return false;
    if (path.extension() == ".enc") return false;
    return allFiles || path.extension() == extension;
}

void encryptFiles(const std::string& key, const std::string& extension, bool allFiles, bool recursive, bool deleteOriginal, CipherType cipher) {
    fs::path selfPath = getExecutablePath();

    auto process = [&](const auto& entry) {
        if (!entry.is_regular_file()) return;
        fs::path inputPath = entry.path();

        if (inputPath == selfPath) {
            std::cout << "Skipping self executable: " << inputPath << "\n";
            return;
        }

        if (!shouldEncryptFile(inputPath, extension, allFiles)) return;

        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile) {
            std::cerr << "Failed to open: " << inputPath << "\n";
            return;
        }

        std::vector<char> buffer((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();

        if (buffer.size() >= VERIFICATION_TAG.size() &&
            std::equal(VERIFICATION_TAG.begin(), VERIFICATION_TAG.end(), buffer.begin())) {
            std::cout << "Skipping already encrypted file: " << inputPath << "\n";
            return;
        }

        applyEncryption(buffer, key, cipher);
        std::vector<char> tagged(VERIFICATION_TAG.begin(), VERIFICATION_TAG.end());
        tagged.insert(tagged.end(), buffer.begin(), buffer.end());

        std::string outPath = inputPath.string() + ".enc";
        std::ofstream outFile(outPath, std::ios::binary);
        if (!outFile) {
            std::cerr << "Failed to write to: " << outPath << "\n";
            return;
        }

        outFile.write(tagged.data(), tagged.size());
        outFile.close();

        if (deleteOriginal) {
            fs::remove(inputPath);
            std::cout << "Deleted: " << inputPath << "\n";
        }

        std::cout << "Encrypted: " << inputPath << " → " << outPath << "\n";
    };

    if (recursive) {
        for (const auto& entry : fs::recursive_directory_iterator(fs::current_path())) process(entry);
    } else {
        for (const auto& entry : fs::directory_iterator(fs::current_path())) process(entry);
    }
}

void decryptFiles(const std::string& key, bool recursive, bool deleteOriginal, CipherType cipher) {
    fs::path selfPath = getExecutablePath();

    auto process = [&](const auto& entry) {
        if (!entry.is_regular_file()) return;
        fs::path inputPath = entry.path();

        if (inputPath == selfPath) {
            std::cout << "Skipping self executable: " << inputPath << "\n";
            return;
        }

        if (inputPath.extension() != ".enc") return;

        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile) {
            std::cerr << "Failed to open: " << inputPath << "\n";
            return;
        }

        std::vector<char> buffer((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();

        if (buffer.size() < VERIFICATION_TAG.size() ||
            !std::equal(VERIFICATION_TAG.begin(), VERIFICATION_TAG.end(), buffer.begin())) {
            std::cerr << "Skipping untagged file: " << inputPath << "\n";
            return;
        }

        buffer.erase(buffer.begin(), buffer.begin() + VERIFICATION_TAG.size());
        applyEncryption(buffer, key, cipher);

        fs::path outputPath = inputPath;
        outputPath.replace_extension(".decrypted" + outputPath.stem().extension().string());

        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) {
            std::cerr << "Failed to write: " << outputPath << "\n";
            return;
        }

        outFile.write(buffer.data(), buffer.size());
        outFile.close();

        if (deleteOriginal) {
            fs::remove(inputPath);
            std::cout << "Deleted: " << inputPath << "\n";
        }

        std::cout << "Decrypted: " << inputPath << " → " << outputPath << "\n";
    };

    if (recursive) {
        for (const auto& entry : fs::recursive_directory_iterator(fs::current_path())) process(entry);
    } else {
        for (const auto& entry : fs::directory_iterator(fs::current_path())) process(entry);
    }
}

CipherType parseCipher(const std::string& name) {
    if (name == "xor") return CipherType::XOR;
    if (name == "rev") return CipherType::REVERSE;
    std::cerr << "Unknown cipher: " << name << " — using XOR by default.\n";
    return CipherType::XOR;
}

void showHelp(const std::string& programName) {
    std::cout << "Flag\tDescription\n"
              << "-e\tEncrypt mode\n"
              << "-d\tDecrypt mode\n"
              << "-a\tEncrypt all files (skips .enc)\n"
              << "<ext>\tEncrypt files with specific extension (e.g. .txt)\n"
              << "<key>\tEncryption key\n"
              << "-r\tRecursively scan subdirectories\n"
              << "-l\tDelete original file after processing\n"
              << "-c\tChoose algorithm: xor or rev\n"
              << "-w\tGenerate a random encryption key (saved to key.txt)\n"
              << "-h\tShow help message\n\n"
              << "Usage examples:\n"
              << programName << " -d myKey -c xor              # Decrypt with XOR\n"
              << programName << " -e -a myKey -c xor -r -l     # Encrypt all files recursively and delete originals\n"
              << programName << " -e .docx myKey -c rev        # Encrypt .docx files using reverse\n"
              << programName << " -e -a -w -c xor -r -l        # Generate random key, encrypt all files, delete originals\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Run with -h to see usage.\n";
        return 1;
    }

    // Show help if -h is passed
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-h") {
            showHelp(argv[0]);
            return 0;
        }
    }

    std::string mode = argv[1];
    std::string extension;
    std::string key;
    bool allFiles = false;
    bool recursive = false;
    bool deleteOriginal = false;
    bool generateKey = false;
    CipherType cipher = CipherType::XOR;

    // Parse flags
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-a") allFiles = true;
        else if (arg == "-r") recursive = true;
        else if (arg == "-l") deleteOriginal = true;
        else if (arg == "-w") generateKey = true;
        else if (arg == "-c" && i + 1 < argc) cipher = parseCipher(argv[++i]);
        else if (key.empty() && !generateKey) {
            if (mode == "-e" && !allFiles && extension.empty() && arg[0] == '.')
                extension = arg;
            else
                key = arg;
        }
    }

    // Handle -w (generate key)
    if (generateKey) {
        key = generateRandomKey();
        std::ofstream outFile("key.txt");
        outFile << key;
        outFile.close();
        std::cout << "Generated key: " << key << "\nSaved to key.txt\n";
    }

    // Run modes
    if (mode == "-e") {
        if (key.empty() || (!allFiles && extension.empty())) {
            std::cerr << "Missing extension or key for encryption. Use -h for help.\n";
            return 1;
        }
        encryptFiles(key, extension, allFiles, recursive, deleteOriginal, cipher);
    } else if (mode == "-d") {
        if (key.empty()) {
            std::cerr << "Missing key for decryption. Use -h for help.\n";
            return 1;
        }
        decryptFiles(key, recursive, deleteOriginal, cipher);
    } else {
        std::cerr << "Invalid mode. Use -e or -d. Run with -h for help.\n";
        return 1;
    }

    return 0;
}

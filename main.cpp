#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>

#include <openssl/sha.h>

namespace fs = std::filesystem;

using namespace std;

// Função para calcular o hash SHA-256 de uma string
std::string calculateHash(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(data.c_str()), data.size(), hash);

    std::ostringstream hashString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashString << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return hashString.str();
}

// Função para converter PDF para texto
bool convertPdfToText(const std::string &pdfPath, const std::string &textPath) {
    std::string command = "pdftotext \"" + pdfPath + "\" \"" + textPath + "\"";
    return (std::system(command.c_str()) == 0);
}


// Função para carregar ficheiros processados a partir do log
void loadProcessedFiles(const std::string &logFile, std::unordered_set<std::string> &processedFiles) {
    std::ifstream logFileStream(logFile);
    if (logFileStream) {
        std::string line;
        while (std::getline(logFileStream, line)) {
            std::string::size_type pos = line.find(": ");
            if (pos != std::string::npos) {
                std::string fileName = line.substr(0, pos);
                processedFiles.insert(fileName);
            }
        }
    }
}

int main() {
    const std::string pdfFolder = "PDF/";
    const std::string contentFolder = "content/";
    const std::string logFile = "files.txt";

    // Conjunto para armazenar os PDFs já processados
    std::unordered_set<std::string> processedFiles;

    // Criar pastas se não existirem
    fs::create_directories(pdfFolder);
    fs::create_directories(contentFolder);

    // Carregar ficheiros processados do log
    loadProcessedFiles(logFile, processedFiles);

    while (true) {
        for (const auto &entry : fs::directory_iterator(pdfFolder)) {
            if (entry.is_regular_file() && entry.path().extension() == ".pdf") {
                const std::string pdfPath = entry.path().filename().string();

                // Verificar se já foi processado
                if (processedFiles.find(pdfPath) == processedFiles.end()) {
                    const std::string textPath = contentFolder + entry.path().stem().string() + ".txt";

                    // Converter PDF para texto
                    if (convertPdfToText(entry.path().string(), textPath)) {
                        std::cout << "Convertido: " << pdfPath << " -> " << textPath << std::endl;

                        // Ler o conteúdo do ficheiro de texto
                        std::ifstream inFile(textPath);
                        std::stringstream buffer;
                        buffer << inFile.rdbuf();

                        // Calcular o hash do conteúdo
                        std::string contentHash = calculateHash(buffer.str());
                        std::cout << "Hash extraído: " << contentHash << std::endl;

                        // Registar o hash e o nome do ficheiro no log
                        std::ofstream logFileStream(logFile, std::ios::app);
                        if (logFileStream) {
                            logFileStream << pdfPath << ": " << contentHash << "\n";
                        } else {
                            std::cerr << "Erro ao abrir o ficheiro de log: " << logFile << std::endl;
                        }

                        // Adicionar à lista de processados
                        processedFiles.insert(pdfPath);
                    } else {
                        std::cerr << "Erro ao converter: " << pdfPath << std::endl;
                    }
                }
            }
        }

        // Intervalo para evitar sobrecarga do sistema
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    return 0;
}


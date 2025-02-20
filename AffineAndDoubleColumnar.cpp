#include <iostream>
#include <string>
#include <cctype>
#include <vector>
#include <algorithm>
#include <chrono> // For measuring execution time

using namespace std;

// Function to calculate modular inverse of 'a' modulo 26
int modInverse(int a, int m) {
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return -1;
}

// Affine Cipher Encryption
string affineEncrypt(const string& plaintext, int a, int b) {
    string encrypted = "";
    for (char c : plaintext) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            c = (a * (c - base) + b) % 26 + base;
        }
        encrypted += c;
    }
    return encrypted;
}

// Affine Cipher Decryption
string affineDecrypt(const string& ciphertext, int a, int b) {
    string decrypted = "";
    int a_inv = modInverse(a, 26);  // Calculate modular inverse of 'a'
    if (a_inv == -1) {
        cout << "Modular inverse of 'a' doesn't exist. Decryption is impossible!" << endl;
        return "";
    }

    for (char c : ciphertext) {
        if (isalpha(c)) {
            char base = islower(c) ? 'a' : 'A';
            c = (a_inv * (c - base - b + 26) % 26) + base;
        }
        decrypted += c;
    }
    return decrypted;
}

// Columnar Transposition Encryption
string columnarEncrypt(const string& text, const string& key) {
    int keyLength = key.length();
    int numRows = (text.length() + keyLength - 1) / keyLength;  // Ensure padding if needed
    vector<vector<char>> grid(numRows, vector<char>(keyLength, 'X'));  // Fill grid with 'X'

    int index = 0;
    for (int i = 0; i < numRows; ++i) {
        for (int j = 0; j < keyLength && index < text.length(); ++j) {
            grid[i][j] = text[index++];
        }
    }

    string encryptedText = "";
    vector<pair<char, int>> sortedKey;
    for (int i = 0; i < key.length(); ++i) {
        sortedKey.push_back({key[i], i});
    }
    sort(sortedKey.begin(), sortedKey.end());

    for (const auto& kv : sortedKey) {
        int col = kv.second;
        for (int row = 0; row < numRows; ++row) {
            encryptedText += grid[row][col];
        }
    }

    return encryptedText;
}

// Columnar Transposition Decryption
string columnarDecrypt(const string& text, const string& key) {
    int keyLength = key.length();
    int numRows = text.length() / keyLength;  // Assuming no padding needed after encryption
    vector<vector<char>> grid(numRows, vector<char>(keyLength));

    // Create a vector of key-value pairs and sort them based on key
    vector<pair<char, int>> sortedKey;
    for (int i = 0; i < key.length(); ++i) {
        sortedKey.push_back({key[i], i});
    }
    sort(sortedKey.begin(), sortedKey.end());

    int index = 0;
    // Fill the grid column by column based on the sorted key
    for (const auto& kv : sortedKey) {
        int col = kv.second;
        for (int row = 0; row < numRows; ++row) {
            grid[row][col] = text[index++];
        }
    }

    // Read the grid row by row to get the decrypted text
    string decryptedText = "";
    for (int row = 0; row < numRows; ++row) {
        for (int col = 0; col < keyLength; ++col) {
            decryptedText += grid[row][col];
        }
    }

    // Remove padding characters ('X')
    decryptedText.erase(remove(decryptedText.begin(), decryptedText.end(), 'X'), decryptedText.end());

    return decryptedText;
}

int main() {
    string plaintext;
    int a, b;
    string key;

    // Input from user
    cout << "Enter the plaintext: ";
    getline(cin, plaintext);

    cout << "Enter the key for Affine Cipher (a and b): ";
    cin >> a >> b;

    cin.ignore();  // To ignore the leftover newline character from previous input

    cout << "Enter the key for Columnar Transposition Cipher: ";
    getline(cin, key);

    // Encryption and Decryption timing for Affine Cipher
    auto start = chrono::high_resolution_clock::now();
    string encryptedAffine = affineEncrypt(plaintext, a, b);
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> affineEncryptTime = end - start;

    start = chrono::high_resolution_clock::now();
    string decryptedAffine = affineDecrypt(encryptedAffine, a, b);
    end = chrono::high_resolution_clock::now();
    chrono::duration<double> affineDecryptTime = end - start;

    // Encryption and Decryption timing for Columnar Transposition
    start = chrono::high_resolution_clock::now();
    string encryptedColumnar = columnarEncrypt(plaintext, key);
    end = chrono::high_resolution_clock::now();
    chrono::duration<double> columnarEncryptTime = end - start;

    start = chrono::high_resolution_clock::now();
    string decryptedColumnar = columnarDecrypt(encryptedColumnar, key);
    end = chrono::high_resolution_clock::now();
    chrono::duration<double> columnarDecryptTime = end - start;

    // Displaying results
    cout << "Affine Cipher Encryption took: " << affineEncryptTime.count() * 1000000 << " microseconds." << endl;
    cout << "Affine Cipher Decryption took: " << affineDecryptTime.count() * 1000000 << " microseconds." << endl;
    cout << "Columnar Transposition Encryption took: " << columnarEncryptTime.count() * 1000000 << " microseconds." << endl;
    cout << "Columnar Transposition Decryption took: " << columnarDecryptTime.count() * 1000000 << " microseconds." << endl;

    // Affine Cipher results
    cout << "\nAffine Cipher:" << endl;
    cout << "Encrypted: " << encryptedAffine << endl;
    cout << "Decrypted: " << decryptedAffine << endl;

    // Columnar Transposition results
    cout << "\nColumnar Transposition:" << endl;
    cout << "Encrypted: " << encryptedColumnar << endl;
    cout << "Decrypted: " << decryptedColumnar << endl;

    return 0;
}


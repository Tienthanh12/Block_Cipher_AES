#include <iostream>
#include <vector>
#include<chrono>

using namespace std;
using namespace std::chrono;




class RC4 {
private:
    std::vector<unsigned char> S;
    int i, j;

    void ksa(const std::vector<unsigned char>& key) {
        S.resize(256);
        for (int i = 0; i < 256; ++i)
            S[i] = i;

        j = 0;
        for (int i = 0; i < 256; ++i) {
            j = (j + S[i] + key[i % key.size()]) % 256;
            std::swap(S[i], S[j]);
        }
    }

    unsigned char prga() {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        return S[(S[i] + S[j]) % 256];
    }

public:
    RC4(const std::vector<unsigned char>& key) {
        ksa(key);
        i = j = 0;
    }

    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data) {
        std::vector<unsigned char> result;
        for (unsigned char byte : data)
            result.push_back(byte ^ prga());
        return result;
    }

    // Decryption is the same as encryption
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& data) {
        return encrypt(data);
    }
};


double TimeToEncrypt_RC4(const vector<unsigned char>& plaintext, const vector<unsigned char>& key) {
    // Start measuring time
    auto start = high_resolution_clock::now();

    // Call encryption function


    RC4 rc4(key);

    vector<unsigned char> ciphertext = rc4.encrypt(plaintext);

    // Stop measuring time
    auto stop = high_resolution_clock::now();

    // Calculate duration in milliseconds
    duration<double, milli> duration_ms = stop - start;
    return duration_ms.count(); // Return time in milliseconds
}

// Define AES S-box
const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


// Define AES round constants
const unsigned char Rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};


// SubBytes transformation
void SubBytes(vector<unsigned char>& state) {
  for (int i = 0; i < 16; ++i) {
    state[i] = sbox[state[i]];
  }
}

// KeyExpansion
void KeyExpansion(const vector<unsigned char>& key, vector<vector<unsigned char>>& w) {
  // Initialize variables
  int Nk = 4; // Number of 32-bit words in the key (AES-128)
  int Nb = 4; // Number of columns (words) in the state (AES is a 4x4 matrix)
  int Nr = 10; // Number of rounds (AES-128)

  int words = Nb * (Nr + 1); // Total number of words needed for all round keys
  vector<unsigned char> tempWord(4);

  // Copy the original key into the initial round key (w[0])
  for (int i = 0; i < Nk; ++i) {
    vector<unsigned char> roundKeyWord;
    for (int j = 0; j < 4; ++j) {
      roundKeyWord.push_back(key[4 * i + j]);
    }
    w.push_back(roundKeyWord);
  }

  // Perform key expansion to generate additional round keys
  for (int i = Nk; i < words; ++i) {
    tempWord = w[i - 1];

    // For every Nk words (once per round key generation cycle)
    if (i % Nk == 0) {
      // RotWord and SubWord operations
      unsigned char temp = tempWord[0];
      tempWord[0] = sbox[tempWord[1]];
      tempWord[1] = sbox[tempWord[2]];
      tempWord[2] = sbox[tempWord[3]];
      tempWord[3] = sbox[temp];

      // XOR with round constant
      tempWord[0] ^= Rcon[i / Nk - 1];
    }

    // XOR with the word Nk positions before
    for (int j = 0; j < 4; ++j) {
      tempWord[j] ^= w[i - Nk][j];
    }

    // Store the generated round key
    w.push_back(tempWord);
  }
}


// AddRoundKey transformation
void AddRoundKey(vector<unsigned char>& state, const vector<unsigned char>& roundKey) {
  for (int i = 0; i < 16; ++i) {
    state[i] ^= roundKey[i];
  }
}

// ShiftRows transformation
void ShiftRows(vector<unsigned char>& state) {
    // Row 1: No shift
    // Row 2: Shift left by 1
    unsigned char temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    // Row 3: Shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    // Row 4: Shift left by 3
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}


// GMul function performs the multiplication in Galois Field (GF(2^8))
unsigned char GMul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char hi_bit_set;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & 1) == 1) {
            p ^= a;
        }
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80) {
            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    return p;
}



// MixColumns transformation
void MixColumns(vector<unsigned char>& state) {
    unsigned char temp[4];
    for (int i = 0; i < 4; ++i) {
        temp[0] = GMul(state[i], 0x02) ^ GMul(state[i + 4], 0x03) ^ state[i + 8] ^ state[i + 12];
        temp[1] = state[i] ^ GMul(state[i + 4], 0x02) ^ GMul(state[i + 8], 0x03) ^ state[i + 12];
        temp[2] = state[i] ^ state[i + 4] ^ GMul(state[i + 8], 0x02) ^ GMul(state[i + 12], 0x03);
        temp[3] = GMul(state[i], 0x03) ^ state[i + 4] ^ state[i + 8] ^ GMul(state[i + 12], 0x02);
        for (int j = 0; j < 4; ++j) {
            state[i + 4 * j] = temp[j];
        }
    }
}


void AES_EncryptBlock(vector<unsigned char>& blockPlaintext, const vector<vector<unsigned char>>& w) {
    // Initial round
    AddRoundKey(blockPlaintext, w[0]);

    // Main rounds (excluding the final round)
    for (int round = 1; round < 10; ++round) {
        SubBytes(blockPlaintext);
        ShiftRows(blockPlaintext);
        MixColumns(blockPlaintext);
        AddRoundKey(blockPlaintext, w[round]);
    }

    // Final round (no MixColumns)
    SubBytes(blockPlaintext);
    ShiftRows(blockPlaintext);
    AddRoundKey(blockPlaintext, w[10]);
}

void AES_Encrypt(const vector<unsigned char>& plaintext, const vector<unsigned char>& key, vector<unsigned char>& ciphertext) {
    vector<vector<unsigned char>> w; // Round keys
    KeyExpansion(key, w);             // Generate round keys

    int numBlocks = plaintext.size() / 16; // Number of 16-byte blocks
    if (plaintext.size() % 16 != 0) {
        numBlocks++; // Add an extra block if the plaintext size is not a multiple of 16
    }

    // Encrypt each block separately
    for (int block = 0; block < numBlocks; ++block) {
        vector<unsigned char> blockPlaintext(16);
        int startIdx = block * 16;
        int endIdx = min((block + 1) * 16, (int)plaintext.size());
        copy(plaintext.begin() + startIdx, plaintext.begin() + endIdx, blockPlaintext.begin());

        // Pad the last block if necessary
        if (endIdx < (block + 1) * 16) {
            blockPlaintext[endIdx - startIdx] = 0x80; // Padding with a single 1-bit followed by zeros
            for (int i = endIdx - startIdx + 1; i < 16; ++i) {
                blockPlaintext[i] = 0x00; // Zero padding
            }
        }

        // Encrypt the block
        AES_EncryptBlock(blockPlaintext, w);

        // Append the ciphertext of this block to the output ciphertext
        ciphertext.insert(ciphertext.end(), blockPlaintext.begin(), blockPlaintext.end());
    }
}

vector<unsigned char> InputPlaintext() {
    vector<unsigned char> plaintext;
    string input;
    cout << "Enter plaintext: ";
    getline(cin, input); // Read plaintext from user

    // Convert input string to vector of unsigned chars
    for (char c : input) {
        plaintext.push_back(static_cast<unsigned char>(c));
    }

    return plaintext;
}


double TimeToEncrypt_AES(const vector<unsigned char>& plaintext, const vector<unsigned char>& key, void (*EncryptFunction)(const vector<unsigned char>&, const vector<unsigned char>&,vector<unsigned char>&)) {
    // Start measuring time
    auto start = high_resolution_clock::now();

    // Call encryption function
    vector<unsigned char> ciphertext;
    EncryptFunction(plaintext, key, ciphertext); // Encrypt plaintext

    // Stop measuring time
    auto stop = high_resolution_clock::now();

    // Calculate duration in milliseconds
    duration<double, milli> duration_ms = stop - start;
    return duration_ms.count(); // Return time in milliseconds
}



int main() {
  // Example usage

  cout<< "Enter the plain text: ";
  vector<unsigned char> key = {0x2a, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x7e, 0x46, 0x93, 0xa8, 0x59};
  vector<unsigned char> plaintext = InputPlaintext();
  vector<unsigned char> ciphertext;



  AES_Encrypt(plaintext, key, ciphertext);

  // cout << "Plain Text: "<<plaintext.size()<<endl;
  // for (int i = 0; i < plaintext.size(); ++i) {
  //   cout << (int)plaintext[i] << " ";
  // }
  // cout << endl;

  // cout << "Cipher Text: "<< ciphertext.size()<<endl;
  // for (int i = 0; i < ciphertext.size(); ++i) {
  //   cout << (int)ciphertext[i] << " ";
  // }

  cout << "=================================================================================="<< endl<<endl;
  double timetaken_RC4 = TimeToEncrypt_RC4(plaintext, key);
  cout<< "RC4 - Time taken to encrypt plaintext: "<< timetaken_RC4<< " miliseconds" << endl;

  cout << endl;
  double timetaken_AES = TimeToEncrypt_AES(plaintext, key, AES_Encrypt);
  cout<< "AES - Time taken to encrypt plaintext: "<< timetaken_AES<< " miliseconds" << endl;

  return 0;
}

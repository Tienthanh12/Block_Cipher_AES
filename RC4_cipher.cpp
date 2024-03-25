#include <iostream>
#include <vector>
#include <algorithm>

class RC4 {
private:
    std::vector<int> S;
    int i, j;

    void ksa(const std::vector<int>& key) 
    {
        S.resize(256);
        for (int i = 0; i < 256; ++i)
            S[i] = i;

        j = 0;
        for (int i = 0; i < 256; ++i) 
        {
            j = (j + S[i] + key[i % key.size()]) % 256;
            std::swap(S[i], S[j]);
        }
        // for( int i : S)
        // std:: cout<< i << " ";
    }

    int prga() {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        // std::cout<<S[(S[i] + S[j]) % 256]<<" "; 
        return S[(S[i] + S[j]) % 256];
    }

public:
    RC4(const std::vector<int>& key) 
    {
        ksa(key);
        i = j = 0;
    }

    std::vector<int> encrypt(const std::vector<int>& data) 
    {
        std::vector<int> result;
        for (int byte : data)
            result.push_back(byte ^ prga());
        return result;
    }

    // Decryption is the same as encryption
    std::vector<int> decrypt(const std::vector<int>& data) {
        return encrypt(data);
    }
};


void Input_Plaintext(std::vector<int> &plaintext)
{
    std::string mess;
    std::getline(std::cin, mess);

    for( int i = 0; i < mess.length(); i ++)
    {
        plaintext.push_back((int)mess[i]);
    }
}

void Input_key(std::vector<int> &key)
{
    std::string seed;
    std::getline(std::cin, seed);
    for(int i = 0; i< seed.length(); i++)
    {
        if(seed[i]<48 || seed[i]> 57)
        key.push_back((int)seed[i]);
        else key.push_back((int)seed[i] - 48);
    }

}

int main() {
    std::vector<int> key ; 
    std::vector<int> plaintext; 
    std::cout<< "Enter the key: ";
    Input_key(key);

    std::cout<<"Enter the message: ";
    Input_Plaintext(plaintext);


    RC4 rc4_encrypt(key);

    // Encrypt
    std::vector<int> encrypted_data = rc4_encrypt.encrypt(plaintext);
    std::cout<< "Encrypted: ";
    for (int byte : encrypted_data)
        std::cout << (char)byte<< " ";
    std::cout << std::endl;

    // Decrypt

    RC4 rc4_decrypt(key);
    std::vector<int> decrypted_data = rc4_decrypt.decrypt(encrypted_data);
    std::cout << "Decrypted: ";
    for (int byte : decrypted_data)
        std::cout << char(byte);
    std::cout << std::endl;

    return 0;
}

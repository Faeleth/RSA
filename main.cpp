#include <iostream>
#include "Rsa.hpp"

int main(){
    srand(time(NULL)); // Seed for random number generator
    const int BIT_SIZE = 40;

    Rsa::Key::KeyPair keys = Rsa::Key::generate_key_pair(BIT_SIZE);

    std::cout << keys.publicKey.to_string() << std::endl;
    std::cout << keys.privateKey.to_string() << std::endl;

    std::string message = "Hello, World";
    std::vector<__int128> encrypted =  Rsa::encoder(message, keys.publicKey);

    std::cout << "Original: " << message << std::endl;
    std::cout << "\nThe encoded message(encrypted by public key)\n";
    for (auto& p : encrypted)
        std::cout << std::to_string(static_cast<long long>(p));

    std::cout << "\n\nThe decoded message(decrypted by private key)\n";
    std::cout << Rsa::decoder(encrypted, keys.privateKey) << std::endl;

    return 0;
}

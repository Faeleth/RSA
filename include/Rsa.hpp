#pragma once

#include <string>
#include <vector>

namespace Rsa{
    namespace {
        namespace utils {
            __int128 mod_exp(__int128 base, __int128 exp, __int128 m);
            bool miller_rabin_test(__int128 n, __int128 d);
            bool is_prime(__int128 n, int k = 5);
            __int128 gcd(__int128 a, __int128 b);
        }
        
        __int128 generate_prime(int bit_size = 2048);
        __int128 mod_inverse(__int128 a, __int128 m);
        __int128 generate_public_exponent(__int128 phi, int bit_size = 2048);
    }

    namespace Key{
        struct PublicKey {
            __int128 e;
            __int128 n;

            std::string to_string() const;
        };

        struct PrivateKey {
            __int128 d;
            __int128 n;

            std::string to_string() const;
        };

        struct KeyPair {
            PublicKey publicKey;
            PrivateKey privateKey;
        };

        KeyPair generate_key_pair(int bit_size = 2048);
    }
    
    std::vector<__int128> encoder(const std::string& encrypt_string, const Key::PublicKey & key);
    std::string decoder(std::vector<__int128> & encoded, const Key::PrivateKey & key);
}
#include <Rsa.hpp>
#include <iomanip>
#include <string>
#include <iostream>
#include <math.h>

namespace Rsa{
    namespace {
        namespace utils {
            __int128 mod_exp(__int128 base, __int128 exp, __int128 m) {
                __int128 result = 1;
                base %= m;
                while (exp > 0) {
                    if (exp & 1)
                        result = (result * base) % m;
                    exp >>= 1;
                    base = (base * base) % m;
                }
                return result;
            }

            bool miller_rabin_test(__int128 n, __int128 d) {
                __int128 a = 2 + rand() % (n - 4);
                __int128 x = mod_exp(a, d, n);
                if (x == 1 || x == n - 1)
                    return true;
                while (d != n - 1) {
                    x = (x * x) % n;
                    d *= 2;
                    if (x == 1)
                        return false;
                    if (x == n - 1)
                        return true;
                }
                return false;
            }

            bool is_prime(__int128 n, int k) {
                if (n <= 1 || n == 4)
                    return false;
                if (n <= 3)
                    return true;

                __int128 d = n - 1;
                while (d % 2 == 0)
                    d /= 2;

                for (int i = 0; i < k; ++i)
                    if (!miller_rabin_test(n, d))
                        return false;

                return true;
            }

            __int128 gcd(__int128 a, __int128 b) {
                while (b != 0) {
                    __int128 temp = b;
                    b = a % b;
                    a = temp;
                }
                return a;
            }
        }
        

        __int128 generate_prime(int bit_size) {
            __int128 min_val = 1;
            __int128 max_val = (static_cast<__int128>(1) << (bit_size - 1)) - 1;

            __int128 randomNumber;
            do {
                randomNumber = (rand() % (max_val - min_val + 1)) + min_val; // Generate random number
            } while (!utils::is_prime(randomNumber)); // Check if it's prime, if not regenerate

            return randomNumber;
        }

        __int128 mod_inverse(__int128 a, __int128 m) {
            __int128 m0 = m;
            __int128 y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1) {
                __int128 q = a / m;
                __int128 t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }

        __int128 generate_public_exponent(__int128 phi, int bit_size) {
            __int128 e = 0; // Commonly chosen public exponent

            while(e >= phi || e <= 1)
                e = generate_prime(bit_size);

            // Check if e and phi are coprime
            while (true) {
                if (utils::gcd(e, phi) == 1)
                    return e;
                // If not coprime, increment e
                e++;
            }
        }

    }

    namespace Key{
        std::string PublicKey::to_string() const {
            return "Public Key: (" + std::to_string(static_cast<long long>(e)) + ", " + std::to_string(static_cast<long long>(n)) + ")";
        }

        std::string PrivateKey::to_string() const {
            return "Private Key: (" + std::to_string(static_cast<long long>(d)) + ", " + std::to_string(static_cast<long long>(n)) + ")";
        }


        KeyPair generate_key_pair(int bit_size) {
            __int128 p = generate_prime(bit_size);
            __int128 q = generate_prime(bit_size);

            __int128 n = p * q;
            __int128 phi = (p - 1) * (q - 1);

            __int128 e = generate_public_exponent(phi);
            __int128 d = mod_inverse(e, phi);

            return { { e, n }, { d, n } };
        }
    }

    std::vector<__int128> encoder(const std::string& encrypt_string, const Key::PublicKey & key) {
        std::vector<__int128> form;
        // calling the encrypting function in encoding function
        for (auto& letter : encrypt_string){
            auto encrypted_letter = utils::mod_exp((__int128)letter, key.e, key.n);
            form.push_back(encrypted_letter);
        }
        return form;
    }

    std::string decoder(std::vector<__int128> & encoded, const Key::PrivateKey & key) {
        std::string s;
        // calling the decrypting function decoding function
        for (auto& num : encoded)
            s += utils::mod_exp(num, key.d, key.n);

        return s;
    }
    
}
#include <iostream>
#include <map>
#include <vector>
#include <cmath>
#include <openssl/sha.h>
#include <string>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/integer/mod_inverse.hpp>
#include <boost/random/ranlux.hpp>

typedef std::map<unsigned long long, unsigned long long> PrimeNumbers;
typedef boost::multiprecision::cpp_int BigNumber;
struct Signing {
    BigNumber r;
    BigNumber s;
};
struct Encrypted {
    BigNumber x;
    BigNumber y;
};
boost::random::mt19937 rng;
BigNumber generate_p() {
    const int bit_length = 4096;

    boost::random::rand48 rng;
    boost::multiprecision::cpp_int random_number = 0;

    for (int i = 0; i < bit_length; ++i) {
        random_number <<= 1;
        random_number |= rng() & 1;
    }
    return random_number;

}
BigNumber mod_pow(BigNumber base, BigNumber exponent, BigNumber modulus) {
    if (exponent == 0) {
        return 1;
    }
    if (exponent % 2 == 0) {
        BigNumber temp = mod_pow(base, exponent / 2, modulus);
        return (temp * temp) % modulus;
    } else {
        return (base * mod_pow(base, exponent - 1, modulus)) % modulus;
    }
}
BigNumber pow (BigNumber base, BigNumber exponent) {
    BigNumber result = base;
    for(BigNumber i = 1; i < exponent; i++) {
        result *= base;
    }
    return result;
}
std::vector<BigNumber> factorize(BigNumber n) {
    std::vector<BigNumber> factors;

    for (BigNumber i = 2; i * i <= n; ++i) {
        while (n % i == 0) {
            factors.push_back(i);
            n /= i;
        }
    }

    if (n > 1) {
        factors.push_back(n);
    }

    return factors;
}

bool is_primitive_root(BigNumber g, BigNumber p) {
    if (g <= 1 || g >= p) {
        return false;
    }

    BigNumber phi = p - 1;
    std::vector<BigNumber> factors = factorize(phi);

    for (const auto& factor : factors) {
        if (mod_pow(g, phi / factor, p) == 1) {
            return false;
        }
    }

    return true;
}

std::vector<BigNumber> find_primitive_roots(BigNumber p) {
    std::vector<BigNumber> roots;
    for (BigNumber g = 2; g < p; ++g) {
        if (is_primitive_root(g, p)) {
            roots.push_back(g);
        }
    }
    return roots;
}
BigNumber generate_random_number(BigNumber lower, BigNumber upper) {
    boost::random::uniform_int_distribution<BigNumber> dist(lower, upper);
    BigNumber random_number = dist(rng);
    return random_number;
}
BigNumber generate_public_key(BigNumber g, BigNumber a, BigNumber p) {
    return mod_pow(g,a,p);
}
BigNumber generate_private_key(BigNumber p) {
    BigNumber a = generate_random_number(2, p-1);
    return a;
}
std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256Context;

    SHA256_Init(&sha256Context);
    SHA256_Update(&sha256Context, input.c_str(), input.length());
    SHA256_Final(hash, &sha256Context);

    std::string hashedValue;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        hashedValue += hex;
    }

    return hashedValue;
}
BigNumber hex_to_bn(const std::string& hex) {
    BigNumber numbered_hash;
    std::stringstream ss;
    ss << std::hex << hex;
    ss >> numbered_hash;
    return numbered_hash;
}
Signing sign_message(BigNumber p, BigNumber g, std::string m, BigNumber a) {
    BigNumber p_minus_one = p-1;
    BigNumber k = generate_random_number(2,p_minus_one);
    BigNumber inversed_k = boost::integer::mod_inverse(k, p_minus_one);;
    BigNumber r = mod_pow(g, k ,p);
    std::string H = sha256( m);
    BigNumber numbered_hash = hex_to_bn(H);
    BigNumber s = ((numbered_hash - a*r) * inversed_k) % p_minus_one;
    return {r,s};
}
BigNumber verificate_message(BigNumber b, BigNumber p, std::string m, BigNumber s, BigNumber r, BigNumber g) {
    BigNumber y = boost::integer::mod_inverse(b, p);
    BigNumber p_minus_one = p-1;
    std::string H = sha256( m);
    BigNumber inverted_s = boost::integer::mod_inverse(s, p_minus_one);
    BigNumber numbered_hash = hex_to_bn(H);
    BigNumber u_one = (numbered_hash * inverted_s)%p_minus_one;
    BigNumber u_two = (r * inverted_s)%p_minus_one;
    BigNumber v = (pow(g, u_one) * pow(y, u_two))%p;
    return v;
}
BigNumber string_to_bn(std::string m) {
    std::string result;
    for (char character : m) {
        result += std::to_string(static_cast<int>(character));
    }
    BigNumber result_number(result);
    return result_number;
}
Encrypted encrypt_message(BigNumber g, BigNumber b, BigNumber m, BigNumber p) {
    BigNumber k = generate_random_number(1, p-1);
    BigNumber x = mod_pow(g, k, p);
    BigNumber y = (pow(b, k) * m) %p;

    return {x,y};
}
BigNumber decrypt_message(const Encrypted& encrypted_info, BigNumber a, BigNumber p) {
    BigNumber s = mod_pow(encrypted_info.x,std::move(a),p);
    BigNumber inverted_s = boost::integer::mod_inverse(s, p);
    BigNumber m = (encrypted_info.y * inverted_s) % p;
    return m;
}
int main() {
    BigNumber p = 171;
    std::string m = "asdasdasdasdsss";
    BigNumber g = find_primitive_roots(p)[2];

    BigNumber a = generate_private_key(p);
    BigNumber b = generate_public_key(g,a,p);

    Signing signing = sign_message(p, g, m, a);
    BigNumber v = verificate_message(b,p,m,signing.s,signing.r,g);

    BigNumber secret_message = 87;
    Encrypted encrypted_info = encrypt_message(g,b,secret_message,p);
    BigNumber decrypted = decrypt_message(encrypted_info, a, p);

    bool is_verified = signing.r == v;
    std::cout<<"Verification: "<<is_verified<<std::endl;
    std::cout<<"Decrypted: "<<decrypted;
    return 0;
}

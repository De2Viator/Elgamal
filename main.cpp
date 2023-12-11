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

PrimeNumbers defactor_number(BigNumber number) {
    PrimeNumbers prime_numbers;
    for(unsigned long long divisor = 2; divisor<=number; ++divisor) {
        while (number % divisor == 0) {
            number /= divisor;
            if(prime_numbers[divisor]) {
                ++prime_numbers[divisor];
            } else {
                prime_numbers[divisor] = 1;
            }
        }
    }

    return prime_numbers;
}
unsigned long long euler_function(BigNumber number) {
    PrimeNumbers prime_numbers = defactor_number(number);
    unsigned long long prime_numbers_amount = 1;
    for (auto & prime_number : prime_numbers) {
        unsigned long long default_number = prime_number.first;
        unsigned long long exponent = prime_number.second;
        prime_numbers_amount *= pow(default_number, exponent)  - pow(default_number, exponent-1);
    }
    return prime_numbers_amount;
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
std::vector<BigNumber> find_primitive_roots(const boost::multiprecision::cpp_int& number) {
    unsigned long long euler_number = euler_function(number);
    PrimeNumbers defactored_number = defactor_number(euler_number);
    std::vector<BigNumber> exponents;
    std::vector<BigNumber> primitive_roots;
    for (auto & it : defactored_number) {
        exponents.push_back(it.first);
    }

    for (unsigned long long i = 2; i < euler_number; ++i) {
        bool is_primitive = true;
        for (BigNumber exponent : exponents) {
            BigNumber mod_pow_result = mod_pow(i,exponent, number);
            if(mod_pow_result == 1) {
                is_primitive = false;
                break;
            }
        }
        if(is_primitive) {
            primitive_roots.push_back(i);
        }
    }

    return primitive_roots;
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
Signing sign_message(BigNumber p, BigNumber g, BigNumber m, BigNumber a) {
    BigNumber p_minus_one = p-1;
    BigNumber k = generate_random_number(2,p_minus_one);
    BigNumber inversed_k = boost::integer::mod_inverse(k, p_minus_one);
    std::cout<<"p-1: "<<p_minus_one<<std::endl;
    std::cout<<"k: "<<k<<std::endl;
    std::cout<<"k^-1: "<<inversed_k<<std::endl;
    BigNumber r = mod_pow(g, k ,p);
    std::cout<<"r: "<<r<<std::endl;
    std::string H = sha256( boost::multiprecision::to_string(m));
    std::cout<<"Hash:"<<H<<std::endl;
    BigNumber numbered_hash = hex_to_bn(H);
    std::cout<<"H: "<<numbered_hash<<std::endl;
    BigNumber test = (numbered_hash - a*r) * inversed_k;
    BigNumber s = ((numbered_hash - a*r) * inversed_k) % p_minus_one;
    std::cout<<"s: "<<s<<std::endl;
    return {r,s};
}
BigNumber verificate_message(BigNumber b, BigNumber p, BigNumber m, BigNumber s, BigNumber r, BigNumber g) {
    BigNumber y = boost::integer::mod_inverse(b, p);
    if(y == 0 ) std::cerr<<"y is 0"<<std::endl;
    std::cout<<"y: "<<y<<std::endl;
    BigNumber p_minus_one = p-1;
    std::string H = sha256( boost::multiprecision::to_string(m));
    BigNumber inverted_s = boost::integer::mod_inverse(s, p_minus_one);
    std::cout<<"s^-1: "<<inverted_s<<std::endl;
    if(inverted_s == 0 ) std::cerr<<"inverted s is 0"<<std::endl;
    BigNumber numbered_hash = hex_to_bn(H);
    BigNumber u_one = (numbered_hash * inverted_s)%p_minus_one;
    std::cout<<"u1: "<<u_one<<std::endl;
    BigNumber u_two = (r * inverted_s)%p_minus_one;
    std::cout<<"u2: "<<u_two<<std::endl;
    BigNumber v = (pow(g, u_one) * pow(y, u_two))%p;
    std::cout<<"v: "<<v<<std::endl;
    return v;
}
Encrypted encrypt_message(BigNumber g, BigNumber b, BigNumber m, BigNumber p) {
    BigNumber k = generate_random_number(1, 100);
    BigNumber x = mod_pow(g, k, p);
    BigNumber y = (pow(b, k) * m)%p;

    return {x,y};
}
BigNumber decrypt_message(Encrypted encrypted_info, BigNumber a, BigNumber p) {
    BigNumber s = mod_pow(encrypted_info.x,a,p);
    BigNumber inverted_s = boost::integer::mod_inverse(s, p);
    BigNumber m = (encrypted_info.y * inverted_s) % p;
    return m;
}
int main() {
    BigNumber p = 1000;
    std::cout<<"p: "<<p<<std::endl;
    BigNumber m = 2311;
    std::cout<<"m: "<<m<<std::endl;
    std::vector<BigNumber> roots = find_primitive_roots(p);
    BigNumber g = roots[5];
    std::cout<<"g: "<<g<<std::endl;

    BigNumber a = generate_private_key(p);
    std::cout<<"a: "<<a<<std::endl;
    BigNumber b = generate_public_key(g,a,p);
    std::cout<<"b: "<<b<<std::endl;

    Signing signing = sign_message(p, g, m, a);
    BigNumber v = verificate_message(b,p,m,signing.s,signing.r,g);

    Encrypted encrypted_info = encrypt_message(g,b,m,p);
    BigNumber decrypted = decrypt_message(encrypted_info, a, p);
    bool is_verified = signing.r == v;
    std::cout<<"Verification: "<<is_verified<<std::endl;
    return 0;
}

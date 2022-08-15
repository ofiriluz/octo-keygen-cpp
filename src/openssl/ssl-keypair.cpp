/**
 * @file ssl-keypair.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-keygen-cpp/openssl/ssl-keypair.hpp"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdexcept>

namespace octo::keygen::ssl
{
SSLKeypair::SSLKeypair(int bits_amount) : bits_amount_(bits_amount), private_key_(nullptr), rsa_key_(nullptr)
{
}

SSLKeypair::~SSLKeypair()
{
    if (private_key_)
    {
        EVP_PKEY_free(private_key_);
    }
}

std::string SSLKeypair::public_key() const
{
    BIO* pubkeybio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPublicKey(pubkeybio, rsa_key_))
    {
        throw std::runtime_error("Could not read public key");
    }

    int pub_len = BIO_pending(pubkeybio);
    char* pub_key = (char*)malloc(pub_len + 1);
    BIO_read(pubkeybio, pub_key, pub_len);
    pub_key[pub_len] = '\0';

    std::string pub_str = pub_key;
    free(pub_key);
    BIO_free_all(pubkeybio);
    return pub_str;
}

std::string SSLKeypair::private_key(const std::string& passphrase) const
{
    BIO* prvkeybio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPrivateKey(prvkeybio, rsa_key_, nullptr, nullptr, 0, nullptr, nullptr))
    {
        throw std::runtime_error("Could not read public key");
    }

    int prv_len = BIO_pending(prvkeybio);
    char* prv_key = (char*)malloc(prv_len + 1);
    BIO_read(prvkeybio, prv_key, prv_len);
    prv_key[prv_len] = '\0';

    std::string prv_str = prv_key;
    free(prv_key);
    BIO_free_all(prvkeybio);
    return prv_str;
}

std::string SSLKeypair::key_pair_type() const
{
    return SSLKEYPAIR_TAG;
}
} // namespace octo::keygen::ssl
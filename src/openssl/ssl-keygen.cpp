/**
 * @file ssl-keygen.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-keygen-cpp/openssl/ssl-keygen.hpp"
#include "octo-keygen-cpp/openssl/ssl-keypair-certificate.hpp"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace octo::keygen::ssl
{
SSLKeygen::SSLKeygen() : logger_("SSLKeygen")
{
}

KeypairCertificatePtr SSLKeygen::do_sign(const SSLKeypairPtr& key_pair, EVP_PKEY* ca, const KeygenOptions& sign_options)
{
    long cert_timeout = 31536000L; // 365 Days
    std::string certificate_issuer = "PSKeygen Self Signed Certificate";
    std::string certificate_subject = "PSKeygen Self Signed Certificate";
    std::string certificate_subject_alt_name = "DNS:localhost";
    if (sign_options.has_option(OPT_KEY_CERTIFICATE_TIMEOUT_SECONDS))
    {
        cert_timeout = std::stol(sign_options.option(OPT_KEY_CERTIFICATE_TIMEOUT_SECONDS));
    }
    if (sign_options.has_option(OPT_KEY_CERTIFICATE_ISSUER))
    {
        certificate_issuer = sign_options.option(OPT_KEY_CERTIFICATE_ISSUER);
    }
    if (sign_options.has_option(OPT_KEY_CERTIFICATE_SUBJECT))
    {
        certificate_subject = sign_options.option(OPT_KEY_CERTIFICATE_SUBJECT);
    }
    if (sign_options.has_option(OPT_KEY_CERTIFICATE_SUBJECT_ALT_NAME))
    {
        certificate_subject_alt_name = sign_options.option(OPT_KEY_CERTIFICATE_SUBJECT_ALT_NAME);
    }
    X509* x509;
    x509 = X509_new();
    if (!x509)
    {
        throw std::runtime_error("Could not generate X509 certificate [Extra Details: -1]");
    }

    // Configure the certificate
    if (!X509_set_version(x509, 2) || !ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) ||
        !X509_gmtime_adj(X509_get_notBefore(x509), 0) || !X509_gmtime_adj(X509_get_notAfter(x509), cert_timeout))
    {
        X509_free(x509);
        throw std::runtime_error("Could not set certificate info");
    }

    // Set the issuer and subject
    X509_NAME* issuer = X509_get_issuer_name(x509);
    X509_NAME* subject = X509_get_subject_name(x509);
    if (!issuer || !subject)
    {
        X509_free(x509);
        throw std::runtime_error("Could not get certificate issuer / subject");
    }

    if (!X509_NAME_add_entry_by_txt(
            issuer, "CN", MBSTRING_ASC, (unsigned char*)certificate_issuer.c_str(), -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(
            subject, "CN", MBSTRING_ASC, (unsigned char*)certificate_subject.c_str(), -1, -1, 0))
    {
        X509_free(x509);
        throw std::runtime_error("Could not set certificate issuer / subject");
    }

    X509_EXTENSION* ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char*)certificate_subject_alt_name.c_str());
    if (!ex || !X509_add_ext(x509, ex, 0))
    {
        X509_free(x509);
        throw std::runtime_error("Could not set certificate subject alternative name");
    }

    // Set the public key
    if (!X509_set_pubkey(x509, key_pair->private_key_))
    {
        X509_free(x509);
        throw std::runtime_error("Could not set certificate key");
    }

    // Sign
    if (!X509_sign(x509, ca, EVP_sha256()))
    {
        X509_free(x509);
        throw std::runtime_error("Could not sign X509 certificate");
    }

    SSLKeypairCertificatePtr cert(new SSLKeypairCertificate());

    cert->certificate_ = x509;

    return cert;
}

KeypairPtr SSLKeygen::generate_keypair(const KeygenOptions& options)
{
    int bits_amount = 2048;
    if (options.has_option(OPT_KEY_PAIR_BITS_AMOUNT))
    {
        bits_amount = std::stoi(options.option(OPT_KEY_PAIR_BITS_AMOUNT));
    }
    EVP_PKEY* private_key = nullptr;
    RSA* rsa_key = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    private_key = EVP_PKEY_new();
    // Generate new private key
    if (!private_key)
    {
        throw std::runtime_error("Could not create private key [Private key gen failed]");
    }

    if (!RSA_generate_key_ex(rsa_key, bits_amount, e, nullptr))
    {
        EVP_PKEY_free(private_key);
        throw std::runtime_error("Could not create private key [RSA gen failed]");
    }
    BN_free(e);

    // Check key
    if (!RSA_check_key(rsa_key))
    {
        RSA_free(rsa_key);
        EVP_PKEY_free(private_key);
        throw std::runtime_error("Could not create private key [RSA check failed]");
    }

    if (!EVP_PKEY_assign_RSA(private_key, rsa_key))
    {
        throw std::runtime_error("Could not create private key [RSA private key envlope assign]");
    }

    // Create the private public keypair
    SSLKeypairPtr keypair(new SSLKeypair(bits_amount));
    keypair->private_key_ = private_key;
    keypair->rsa_key_ = rsa_key;

    return keypair;
}

KeypairCertificatePtr SSLKeygen::sign_key_pair_with_ca(const KeypairPtr& key_pair,
                                                       const std::string& ca,
                                                       const KeygenOptions& sign_options)
{
    // Make sure that we received an ssh key pair and cast it
    if (key_pair->key_pair_type() != SSLKEYPAIR_TAG)
    {
        throw std::runtime_error("Invalid key pair for SSLKeygen");
    }

    logger_.info() << "Preparing to sign key with ca";
    logger_.debug() << "Options are: " << sign_options.format_options();

    // Cast it
    SSLKeypairPtr ssl_key_pair = std::dynamic_pointer_cast<SSLKeypair>(key_pair);

    // Load the CA
    BIO* ca_buff = BIO_new_mem_buf((void*)ca.c_str(), ca.size());
    EVP_PKEY* ca_key = nullptr;
    ca_key = PEM_read_bio_PrivateKey(ca_buff, &ca_key, NULL, NULL);
    if (!ca_key)
    {
        BIO_free(ca_buff);
        throw std::runtime_error("Could not convert CA to EVP_PKEY");
    }

    try
    {
        KeypairCertificatePtr cert = do_sign(ssl_key_pair, ca_key, sign_options);
        BIO_free(ca_buff);
        EVP_PKEY_free(ca_key);
        return cert;
    }
    catch (std::runtime_error& e)
    {
        BIO_free(ca_buff);
        EVP_PKEY_free(ca_key);
        throw;
    }
}

KeypairCertificatePtr SSLKeygen::sign_key_pair(const KeypairPtr& key_pair, const KeygenOptions& sign_options)
{
    // Make sure that we received an ssh key pair and cast it
    if (key_pair->key_pair_type() != SSLKEYPAIR_TAG)
    {
        throw std::runtime_error("Invalid key pair for SSLKeygen");
    }

    logger_.info() << "Preparing to sign key pair";
    logger_.debug() << "Options are: " << sign_options.format_options();

    // Cast it
    SSLKeypairPtr ssl_key_pair = std::dynamic_pointer_cast<SSLKeypair>(key_pair);

    return do_sign(ssl_key_pair, ssl_key_pair->private_key_, sign_options);
}
} // namespace octo::keygen::ssl
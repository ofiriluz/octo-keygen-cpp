/**
 * @file ssl-keypair-certificate-chain.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-keygen-cpp/openssl/ssl-keypair-certificate-chain.hpp"
#include "octo-keygen-cpp/openssl/ssl-keypair-certificate.hpp"
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <functional>
#include <memory>
#include <stdexcept>

namespace octo::keygen::ssl
{
SSLKeypairCertificateChain::SSLKeypairCertificateChain(STACK_OF(X509) * chain,
                                                       bool chain_ownership,
                                                       std::string identifier)
    : chain_(chain),
      chain_ownership_(chain_ownership),
      identifier_(std::move(identifier)),
      logger_("SSLKeypairCertificateChain")
{
}
SSLKeypairCertificateChain::~SSLKeypairCertificateChain()
{
    if (chain_ && chain_ownership_)
    {
        sk_X509_free(chain_);
    }
}
std::unique_ptr<SSLKeypairCertificateChain> SSLKeypairCertificateChain::load_certificate_chain(
    encryption::SecureStringUniquePtr data, const std::string& identifier)
{
    auto bio = std::unique_ptr<BIO, std::function<void(BIO*)>>(BIO_new(BIO_s_mem()), [](BIO* bio) { BIO_free(bio); });

    if (!BIO_puts(bio.get(), data->get().data()))
    {
        throw std::runtime_error("Could not write certificate to bio");
    }
    auto ssl_certificate_chain = std::make_unique<SSLKeypairCertificateChain>(nullptr, true, identifier);
    auto cert_chain_info = std::unique_ptr<STACK_OF(X509_INFO), std::function<void(STACK_OF(X509_INFO)*)>>(
        PEM_X509_INFO_read_bio(bio.get(), nullptr, nullptr, nullptr),
        [](STACK_OF(X509_INFO) * info) { sk_X509_INFO_pop_free(info, X509_INFO_free); });
    if (!cert_chain_info)
    {
        throw std::runtime_error("Could not load PEM certificate chain");
    }
    ssl_certificate_chain->chain_ = sk_X509_new_null();
    if (!ssl_certificate_chain->chain_)
    {
        throw std::runtime_error("Could not allocate chain");
    }
    for (int i = 0; i < sk_X509_INFO_num(cert_chain_info.get()); i++)
    {
        X509_INFO* xi = sk_X509_INFO_value(cert_chain_info.get(), i);
        if (xi->x509)
        {
            sk_X509_push(ssl_certificate_chain->chain_, xi->x509);
            xi->x509 = nullptr;
        }
    }
    return std::move(ssl_certificate_chain);
}
std::vector<std::string> SSLKeypairCertificateChain::certificate_chain() const
{
    std::vector<std::string> certs;
    if (!chain_)
    {
        return certs;
    }
    certs.reserve(sk_X509_num(chain_));
    for (int i = 0; i < sk_X509_num(chain_); ++i)
    {
        X509* x509_cert = sk_X509_value(chain_, i);
        auto certbio =
            std::unique_ptr<BIO, std::function<void(BIO*)>>(BIO_new(BIO_s_mem()), [](BIO* bio) { BIO_free_all(bio); });
        if (!PEM_write_bio_X509(certbio.get(), x509_cert))
        {
            throw std::runtime_error("Could not read certificate");
        }

        int const cert_len = BIO_pending(certbio.get());
        char* cert = static_cast<char*>(malloc(cert_len + 1));
        if (!BIO_read(certbio.get(), cert, cert_len))
        {
            free(cert);
            throw std::runtime_error("Could not write certificate");
        }
        cert[cert_len] = '\0';

        std::string cert_str = cert;
        free(cert);

        certs.push_back(std::move(cert_str));
    }

    return std::move(certs);
}
bool SSLKeypairCertificateChain::is_valid_chain(const SSLKeypairCertificate* cert,
                                                const SSLKeypairCertificateChain* cert_chain)
{
    static const auto PURPOSES = {X509_PURPOSE_SSL_SERVER, X509_PURPOSE_SSL_CLIENT, X509_PURPOSE_ANY};

    if (!chain_ || sk_X509_num(chain_) == 0)
    {
        logger_.warning(identifier_) << "Cannot validate chain, empty";
        return false;
    }

    auto store = std::unique_ptr<X509_STORE, std::function<void(X509_STORE*)>>(
        X509_STORE_new(), [](X509_STORE* store) { X509_STORE_free(store); });
    for (int i = 0; i < sk_X509_num(chain_); i++)
    {
        auto rc = X509_STORE_add_cert(store.get(), sk_X509_value(chain_, i));
        if (!rc)
        {
            logger_.warning(identifier_) << "Failed to add cert to store";
            return false;
        }
    }

    X509_STORE_set_flags(store.get(), X509_V_FLAG_PARTIAL_CHAIN);

    logger_.info(identifier_)
        .formatted("Checking if ca chain with length of [{}] with subject is a valid chain of cert with subject [{}]",
                   sk_X509_num(chain_),
                   cert->subject_name());
    for (auto const purpose : PURPOSES)
    {
        logger_.info(identifier_).formatted("Checking with purpose {}", purpose);
        auto ctx = std::unique_ptr<X509_STORE_CTX, std::function<void(X509_STORE_CTX*)>>(
            X509_STORE_CTX_new(), [](X509_STORE_CTX* store) { X509_STORE_CTX_free(store); });
        if (!X509_STORE_CTX_init(ctx.get(), store.get(), cert->ssl_certificate(), cert_chain->ssl_certificate_chain()))
        {
            continue;
        }
        X509_STORE_CTX_set_purpose(ctx.get(), purpose);
        auto rc = X509_verify_cert(ctx.get());
        auto const err = X509_STORE_CTX_get_error(ctx.get());
        if (rc == 1)
        {
            logger_.info(identifier_).formatted("Purpose {} is a valid certificate chain", purpose);
            return true;
        }
        else if (err != X509_V_ERR_INVALID_PURPOSE)
        {
            logger_.warning(identifier_)
                .formatted("An error occurred while checking purpose [{}] - [{}] - [{}] - [{}]",
                           purpose,
                           err,
                           X509_verify_cert_error_string(err),
                           X509_STORE_CTX_get_error_depth(ctx.get()));
            break;
        }
        logger_.info(identifier_).formatted("Purpose {} does not fit", purpose);
    }
    return false;
}
bool SSLKeypairCertificateChain::is_any_ca() const
{
    for (int i = 0; i < sk_X509_num(chain_); i++)
    {
        auto cert = sk_X509_value(chain_, i);
        if (X509_check_purpose(cert, X509_PURPOSE_SSL_CLIENT, 1) ||
            X509_check_purpose(cert, X509_PURPOSE_SSL_SERVER, 1) || X509_check_purpose(cert, X509_PURPOSE_ANY, 1))
        {
            return true;
        }
    }
    return false;
}
bool SSLKeypairCertificateChain::is_all_valid() const
{
    std::time_t current_time;
    std::time(&current_time);
    for (int i = 0; i < sk_X509_num(chain_); i++)
    {
        auto cert = sk_X509_value(chain_, i);
        if (!X509_cmp_time(X509_get_notBefore(cert), &current_time) ||
            !X509_cmp_time(X509_get_notAfter(cert), &current_time))
        {
            return false;
        }
    }
    return true;
}
STACK_OF(X509) * SSLKeypairCertificateChain::ssl_certificate_chain() const
{
    return chain_;
}
bool SSLKeypairCertificateChain::ssl_chain_ownership() const
{
    return chain_ownership_;
}
std::string SSLKeypairCertificateChain::identifier() const
{
    return identifier_;
}
std::vector<std::unique_ptr<SSLKeypairCertificate>> SSLKeypairCertificateChain::as_ssl_certificates() const
{
    std::vector<std::unique_ptr<SSLKeypairCertificate>> certs;
    certs.reserve(sk_X509_num(chain_));
    for (int i = 0; i < sk_X509_num(chain_); i++)
    {
        auto cert = sk_X509_value(chain_, i);
        certs.push_back(std::make_unique<SSLKeypairCertificate>(cert, false, identifier_));
    }
    return std::move(certs);
}
void SSLKeypairCertificateChain::set_ssl_certificate_chain(STACK_OF(X509) * chain, bool chain_ownership)
{
    if (chain_ && chain_ownership_)
    {
        sk_X509_free(chain_);
    }
    chain_ = chain;
    chain_ownership_ = chain_ownership;
}
} // namespace octo::keygen::ssl

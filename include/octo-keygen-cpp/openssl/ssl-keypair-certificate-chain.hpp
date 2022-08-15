/**
 * @file ssl-keypair-certificate-chain.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SSL_KEYPAIR_CERTIFICATE_CHAIN_HPP_
#define SSL_KEYPAIR_CERTIFICATE_CHAIN_HPP_

#include "octo-keygen-cpp/keypair-certificate-chain.hpp"
#include "octo-encryption-cpp/encryptors/encrypted-string.hpp"
#include <openssl/x509v3.h>
#include <octo-logger-cpp/logger.hpp>

namespace octo::keygen::ssl
{
class SSLKeypairCertificate;
class SSLKeypairCertificateChain : public KeypairCertificateChain
{
  private:
    STACK_OF(X509) * chain_;
    bool chain_ownership_;
    std::string identifier_;
    logger::Logger logger_;

  public:
    explicit SSLKeypairCertificateChain(STACK_OF(X509) * chain = nullptr,
                                        bool chain_ownership = false,
                                        std::string identifier = "");
    ~SSLKeypairCertificateChain() override;

    static std::unique_ptr<SSLKeypairCertificateChain> load_certificate_chain(encryption::SecureStringUniquePtr data,
                                                                              const std::string& identifier = "");

    [[nodiscard]] std::vector<std::string> certificate_chain() const override;
    [[nodiscard]] bool is_valid_chain(const SSLKeypairCertificate* cert, const SSLKeypairCertificateChain* cert_chain);
    [[nodiscard]] bool is_any_ca() const;
    [[nodiscard]] bool is_all_valid() const;
    [[nodiscard]] STACK_OF(X509) * ssl_certificate_chain() const;
    [[nodiscard]] bool ssl_chain_ownership() const;
    [[nodiscard]] std::string identifier() const;
    [[nodiscard]] std::vector<std::unique_ptr<SSLKeypairCertificate>> as_ssl_certificates() const;

    void set_ssl_certificate_chain(STACK_OF(X509) * chain, bool chain_ownership = false);

    friend class SSLKeygen;
};
typedef std::shared_ptr<SSLKeypairCertificateChain> SSLKeypairCertificateChainPtr;
typedef std::unique_ptr<SSLKeypairCertificateChain> SSLKeypairCertificateChainUniquePtr;
} // namespace octo::keygen::ssl

#endif

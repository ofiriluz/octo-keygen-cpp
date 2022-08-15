/**
 * @file ssl-keygen.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SSL_KEYGEN_HPP_
#define SSL_KEYGEN_HPP_

#include "octo-keygen-cpp/keygen.hpp"
#include "ssl-keypair.hpp"
#include <octo-logger-cpp/logger.hpp>

namespace octo::keygen::ssl
{
static constexpr const char OPT_KEY_PAIR_BITS_AMOUNT[] = "KeyPairBitsAmount";
static constexpr const char OPT_KEY_CERTIFICATE_TIMEOUT_SECONDS[] = "CertificateTimeoutSeconds";
static constexpr const char OPT_KEY_CERTIFICATE_ISSUER[] = "CertificateIssuer";
static constexpr const char OPT_KEY_CERTIFICATE_SUBJECT[] = "CertificateSubject";
static constexpr const char OPT_KEY_CERTIFICATE_SUBJECT_ALT_NAME[] = "CertificateSubjectAltName";

class SSLKeygen : public Keygen
{
  private:
    logger::Logger logger_;

  private:
    KeypairCertificatePtr do_sign(const SSLKeypairPtr& key_pair, EVP_PKEY* ca, const KeygenOptions& sign_options);

  public:
    SSLKeygen();
    ~SSLKeygen() override = default;

    [[nodiscard]] KeypairPtr generate_keypair(const KeygenOptions& options) override;
    [[nodiscard]] KeypairCertificatePtr sign_key_pair_with_ca(const KeypairPtr& key_pair,
                                                              const std::string& ca,
                                                              const KeygenOptions& sign_options) override;
    [[nodiscard]] KeypairCertificatePtr sign_key_pair(const KeypairPtr& key_pair,
                                                      const KeygenOptions& sign_options) override;
};
} // namespace octo::keygen::ssl

#endif
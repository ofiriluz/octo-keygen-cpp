/**
 * @file ssl-keypair-certificate.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SSL_KEYPAIR_CERTIFICATE_HPP_
#define SSL_KEYPAIR_CERTIFICATE_HPP_

#include "octo-keygen-cpp/keypair-certificate.hpp"
#include <octo-encryption-cpp/encryptors/encrypted-string.hpp>
#include <octo-logger-cpp/logger.hpp>
#include <regex>
#include <set>
#include <string_view>
#include <unordered_map>

typedef struct x509_st X509;

namespace octo::keygen::ssl
{
static constexpr const char SSLKEYPAIRCERTIFICATE_TAG[] = "SSLKeypairCertificate";
class SSLKeypairCertificateChain;

class SSLKeypairCertificate : public KeypairCertificate
{
  public:
    enum class FingerprintAlgorithm : uint8_t
    {
        SHA1,
        SHA256,
        MD5,
    };

  private:
    static const std::regex PATTERNED_NAME_REGEX;

  protected:
    X509* certificate_;
    logger::Logger logger_;
    bool cert_ownership_;
    std::string identifier_;

  private:
    [[nodiscard]] std::string fingerprint(std::string_view algorithm) const noexcept(false);

  public:
    explicit SSLKeypairCertificate(X509* certificate = nullptr,
                                   bool cert_ownership = true,
                                   std::string identifier = "");
    ~SSLKeypairCertificate() override;

    // Compare certificates
    bool operator==(const SSLKeypairCertificate& other) const;

    static bool add_extension(X509* certificate, int nid, const std::string& value);
    static std::string get_extension(X509* certificate, int nid);
    static bool delete_extension(X509* certificate, int nid);
    static std::unique_ptr<SSLKeypairCertificate> load_certificate(encryption::SecureStringUniquePtr data,
                                                                   const std::string& identifier = "");
    static bool compare_certificates(const SSLKeypairCertificate* cert1, const SSLKeypairCertificate* cert2);
    [[nodiscard]] static std::string_view algorithm_to_digest(FingerprintAlgorithm algorithm) noexcept(false);

    [[nodiscard]] bool add_certificate_extension(int nid, const std::string& value);
    [[nodiscard]] std::string get_certificate_extension(int nid);
    [[nodiscard]] bool delete_certificate_extension(int nid);

    [[nodiscard]] bool is_valid_chain(const SSLKeypairCertificate* cert, const SSLKeypairCertificateChain* cert_chain);
    [[nodiscard]] std::string certificate() const override;
    [[nodiscard]] std::string certificate_type() const override;
    [[nodiscard]] std::string pretty_print_certificate_info() const override;

    [[nodiscard]] X509* ssl_certificate() const;
    [[nodiscard]] bool ssl_cert_ownership() const;
    [[nodiscard]] std::string pem_certificate() const;
    [[nodiscard]] bool is_valid() const;
    [[nodiscard]] bool is_client_ca() const;
    [[nodiscard]] bool is_server_ca() const;
    [[nodiscard]] bool is_any_ca() const;
    [[nodiscard]] bool is_ca() const;
    [[nodiscard]] bool is_valid_hostname(const std::string& hostname) const;
    [[nodiscard]] std::string subject_name() const;
    [[nodiscard]] std::string subject_common_name() const;
    [[nodiscard]] std::string issuer() const;
    /// @brief Generates the fingerprint of the certificate by the requested algorithm
    [[nodiscard]] std::string fingerprint(FingerprintAlgorithm algorithm) const;
    // @brief Generates all the fingerprints of the certificate with all supported algorithms
    [[nodiscard]] std::unordered_map<std::string, std::string> fingerprints() const;

    [[nodiscard]] std::set<std::string> alternate_names() const;
    [[nodiscard]] std::string identifier() const;

    friend class SSLKeygen;
    friend class SSLKeypairCertificateChain;
};
typedef std::shared_ptr<SSLKeypairCertificate> SSLKeypairCertificatePtr;
typedef std::unique_ptr<SSLKeypairCertificate> SSLKeypairCertificateUniquePtr;
} // namespace octo::keygen::ssl

#endif

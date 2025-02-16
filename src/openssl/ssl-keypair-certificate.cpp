/**
 * @file ssl-keypair-certificate.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-keygen-cpp/openssl/ssl-keypair-certificate.hpp"
#include "octo-keygen-cpp/openssl/ssl-keypair-certificate-chain.hpp"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <stdexcept>
#include <cstring>
#include <memory>
#include <vector>
#include <functional>
#include <ctime>
#include <fmt/format.h>
#include <regex>
#include <iostream>

namespace
{
constexpr const auto MAX_SUBJECT_NAME_BUFFER_SIZE = 512;
constexpr const auto MAX_ISSUER_NAME_BUFFER_SIZE = 512;
} // namespace

namespace octo::keygen::ssl
{
const std::regex SSLKeypairCertificate::PATTERNED_NAME_REGEX = std::regex("^\\*\\..*$");

SSLKeypairCertificate::SSLKeypairCertificate(X509* certificate, bool cert_ownership, std::string identifier)
    : certificate_(certificate),
      logger_("SSLKeypairCertificate"),
      cert_ownership_(cert_ownership),
      identifier_(std::move(identifier))
{
}

SSLKeypairCertificate::~SSLKeypairCertificate()
{
    if (certificate_ && cert_ownership_)
    {
        X509_free(certificate_);
    }
}

std::string SSLKeypairCertificate::certificate() const
{
    auto certbio =
        std::unique_ptr<BIO, std::function<void(BIO*)>>(BIO_new(BIO_s_mem()), [](BIO* bio) { BIO_free_all(bio); });
    if (!PEM_write_bio_X509(certbio.get(), certificate_))
    {
        throw std::runtime_error("Could not read certificate");
    }

    int cert_len = BIO_pending(certbio.get());
    char* cert = static_cast<char*>(malloc(cert_len + 1));
    if (!BIO_read(certbio.get(), cert, cert_len))
    {
        free(cert);
        throw std::runtime_error("Could not write certificate");
    }
    cert[cert_len] = '\0';

    std::string cert_str = cert;
    free(cert);

    return cert_str;
}

std::string SSLKeypairCertificate::certificate_type() const
{
    return SSLKEYPAIRCERTIFICATE_TAG;
}

std::string SSLKeypairCertificate::pretty_print_certificate_info() const
{
    auto certbio =
        std::unique_ptr<BIO, std::function<void(BIO*)>>(BIO_new(BIO_s_mem()), [](BIO* bio) { BIO_free_all(bio); });
    if (!X509_print_ex(certbio.get(), certificate_, 0, 0))
    {
        throw std::runtime_error("Could not write certificate");
    }

    int cert_len = BIO_pending(certbio.get());
    char* cert = static_cast<char*>(malloc(cert_len + 1));
    if (!BIO_read(certbio.get(), cert, cert_len))
    {
        free(cert);
        throw std::runtime_error("Could not write certificate");
    }
    cert[cert_len] = '\0';

    std::string cert_str = cert;
    free(cert);

    return cert_str;
}

std::string SSLKeypairCertificate::pem_certificate() const
{
    auto certbio =
        std::unique_ptr<BIO, std::function<void(BIO*)>>(BIO_new(BIO_s_mem()), [](BIO* bio) { BIO_free_all(bio); });
    if (!PEM_write_bio_X509(certbio.get(), certificate_))
    {
        throw std::runtime_error("Could not write certificate");
    }

    int cert_len = BIO_pending(certbio.get());
    char* cert = static_cast<char*>(malloc(cert_len + 1));
    if (!BIO_read(certbio.get(), cert, cert_len))
    {
        free(cert);
        throw std::runtime_error("Could not write certificate");
    }
    cert[cert_len] = '\0';

    std::string cert_str = cert;
    free(cert);

    return cert_str;
}

bool SSLKeypairCertificate::is_valid() const
{
    std::time_t current_time;
    std::time(&current_time);
    return (X509_cmp_time(X509_get_notBefore(certificate_), &current_time) == -1 &&
            X509_cmp_time(X509_get_notAfter(certificate_), &current_time) == 1);
}

bool SSLKeypairCertificate::is_client_ca() const
{
    return X509_check_purpose(certificate_, X509_PURPOSE_SSL_CLIENT, 1);
}

bool SSLKeypairCertificate::is_server_ca() const
{
    return X509_check_purpose(certificate_, X509_PURPOSE_SSL_SERVER, 1);
}

bool SSLKeypairCertificate::is_any_ca() const
{
    return X509_check_purpose(certificate_, X509_PURPOSE_ANY, 1);
}

bool SSLKeypairCertificate::is_ca() const
{
    return is_client_ca() || is_server_ca() || is_any_ca();
}

bool SSLKeypairCertificate::is_valid_hostname(const std::string& hostname) const
{
    // Get certificate subject common name and alternate names
    auto const hostname_without_machine = hostname.substr(hostname.find_first_of('.') + 1, hostname.size());
    auto alternate_names_patterns = alternate_names();
    alternate_names_patterns.insert(alternate_names_patterns.begin(), subject_name());
    alternate_names_patterns.insert(alternate_names_patterns.begin(), subject_common_name());
    logger_.info(identifier_)
        .formatted("Checking if certificate is valid against hostname [{}] or hostname without machine [{}] "
                   "with alternate names [{}]",
                   hostname,
                   hostname_without_machine,
                   fmt::format("{}", fmt::join(alternate_names_patterns, ", ")));

    // Check if any pattern matches the hostname
    return std::any_of(
        alternate_names_patterns.cbegin(), alternate_names_patterns.cend(), [&](const std::string& pattern) {
            return pattern == hostname ||
                   (std::regex_match(pattern, PATTERNED_NAME_REGEX) && !hostname_without_machine.empty() &&
                    pattern.substr(2, pattern.size()) == hostname_without_machine);
        });
}

bool SSLKeypairCertificate::is_valid_chain(const SSLKeypairCertificate* cert,
                                           const SSLKeypairCertificateChain* cert_chain)
{
    static const auto PURPOSES = {X509_PURPOSE_SSL_SERVER, X509_PURPOSE_SSL_CLIENT, X509_PURPOSE_ANY};

    if (!certificate_)
    {
        logger_.warning(identifier_) << "Cannot validate certificate, empty";
        return false;
    }

    auto store = std::unique_ptr<X509_STORE, std::function<void(X509_STORE*)>>(
        X509_STORE_new(), [](X509_STORE* store) { X509_STORE_free(store); });
    auto rc = X509_STORE_add_cert(store.get(), certificate_);
    if (!rc)
    {
        logger_.warning(identifier_) << "Failed to add cert to store";
        return false;
    }
    X509_STORE_set_flags(store.get(), X509_V_FLAG_PARTIAL_CHAIN);

    logger_.info(identifier_)
        .formatted("Checking if ca with subject [{}] is a valid chain of cert with subject [{}]",
                   subject_name(),
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
        rc = X509_verify_cert(ctx.get());
        auto const err = X509_STORE_CTX_get_error(ctx.get());
        if (rc == 1)
        {
            logger_.info(identifier_).formatted("Purpose {} is a valid certificate", purpose);
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

std::string SSLKeypairCertificate::subject_name() const
{
    char buffer[MAX_SUBJECT_NAME_BUFFER_SIZE];
    X509_NAME_oneline(X509_get_subject_name(certificate_), buffer, MAX_SUBJECT_NAME_BUFFER_SIZE);
    return {buffer};
}

std::string SSLKeypairCertificate::subject_common_name() const
{
    unsigned char* common_name;
    auto subj_name = X509_get_subject_name(certificate_);
    auto cn_idx = X509_NAME_get_index_by_NID(subj_name, NID_commonName, -1);
    if (cn_idx < 0)
    {
        return subject_name();
    }
    auto entry = X509_NAME_get_entry(subj_name, cn_idx);

    if (!entry)
    {
        return subject_name();
    }

    auto entry_data = X509_NAME_ENTRY_get_data(entry);

    if (!entry_data)
    {
        return subject_name();
    }
    auto length = ASN1_STRING_to_UTF8(&common_name, entry_data);

    if (length < 0)
    {
        return subject_name();
    }
    auto common_name_str = std::string(reinterpret_cast<const char*>(common_name), length);
    OPENSSL_free(common_name);
    return common_name_str;
}

std::string SSLKeypairCertificate::issuer() const
{
    char buffer[MAX_ISSUER_NAME_BUFFER_SIZE];
    X509_NAME_oneline(X509_get_issuer_name(certificate_), buffer, MAX_ISSUER_NAME_BUFFER_SIZE);
    return {buffer};
}

std::string SSLKeypairCertificate::fingerprint(std::string_view algorithm, std::string_view separator) const
    noexcept(false)
{
    std::uint32_t hash_size;
    std::vector<unsigned char> buffer(EVP_MAX_MD_SIZE);
    auto const digest = EVP_get_digestbyname(algorithm.data());
    if (!digest)
    {
        throw std::runtime_error("Invalid fingerprint algorithm");
    }
    X509_digest(certificate_, digest, &buffer[0], &hash_size);
    return fmt::format("{:02x}", fmt::join(buffer.cbegin(), buffer.cbegin() + hash_size, separator));
}

std::string SSLKeypairCertificate::fingerprint(SSLKeypairCertificate::FingerprintAlgorithm algorithm,
                                               std::string_view separator) const
{
    return fingerprint(algorithm_to_digest(algorithm), separator);
}

std::unordered_map<std::string, std::string> SSLKeypairCertificate::fingerprints(std::string_view separator) const
{
    static auto constexpr algorithms = {
        FingerprintAlgorithm::SHA1, FingerprintAlgorithm::SHA256, FingerprintAlgorithm::MD5};
    return fingerprints(algorithms, separator);
}

std::unordered_map<std::string, std::string> SSLKeypairCertificate::fingerprints(
    std::unordered_set<FingerprintAlgorithm> const& algorithms, std::string_view separator) const
{
    std::unordered_map<std::string, std::string> fingerprints;
    for (auto const& algorithm : algorithms)
    {
        fingerprints.emplace(algorithm_to_digest(algorithm), fingerprint(algorithm, separator));
    }
    return fingerprints;
}

std::string_view SSLKeypairCertificate::algorithm_to_digest(
    SSLKeypairCertificate::FingerprintAlgorithm algorithm) noexcept(false)
{
    switch (algorithm)
    {
        case FingerprintAlgorithm::SHA1:
            return "sha1";
        case FingerprintAlgorithm::SHA256:
            return "sha256";
        case FingerprintAlgorithm::MD5:
            return "md5";
    }
    throw std::runtime_error("Invalid fingerprint algorithm");
}

std::set<std::string> SSLKeypairCertificate::alternate_names() const
{
    unsigned char* raw_cert_name = nullptr;
    auto alt_names =
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(certificate_, NID_subject_alt_name, nullptr, nullptr));
    auto alt_name_count = sk_GENERAL_NAME_num(alt_names);
    std::set<std::string> sans;

    for (auto i = 0; i < alt_name_count; ++i)
    {
        GENERAL_NAME const* san = sk_GENERAL_NAME_value(alt_names, i);
        switch (san->type)
        {
            case GEN_DNS:
            {
                ASN1_STRING_to_UTF8(&raw_cert_name, san->d.dNSName);
                if (static_cast<size_t>(ASN1_STRING_length(san->d.dNSName)) !=
                    strlen(reinterpret_cast<const char*>(raw_cert_name)))
                {
                    // Null byte poisoning possible here, check and ignore accordingly
                    OPENSSL_free(raw_cert_name);
                    break;
                }
                auto cert_name = std::string(reinterpret_cast<const char*>(raw_cert_name),
                                             strlen(reinterpret_cast<const char*>(raw_cert_name)));
                // Check if FQDN ends with "." since it is valid and we can ignore the dot
                if (cert_name[cert_name.size() - 1] == '.')
                {
                    cert_name[cert_name.size() - 1] = '\0';
                }
                // Add to the final list of alternate names
                sans.emplace(cert_name);
                OPENSSL_free(raw_cert_name);
                break;
            }
            case GEN_IPADD:
            {
                if (san->d.iPAddress->length == 4)
                {
                    auto ip_addr = fmt::format("{}.{}.{}.{}",
                                               san->d.iPAddress->data[0],
                                               san->d.iPAddress->data[1],
                                               san->d.iPAddress->data[2],
                                               san->d.iPAddress->data[3]);
                    sans.emplace(ip_addr);
                }
                break;
            }
            case GEN_EMAIL:
            {
                ASN1_STRING_to_UTF8(&raw_cert_name, san->d.rfc822Name);
                if (static_cast<size_t>(ASN1_STRING_length(san->d.rfc822Name)) !=
                    strlen(reinterpret_cast<const char*>(raw_cert_name)))
                {
                    // Null byte poisoning possible here, check and ignore accordingly
                    OPENSSL_free(raw_cert_name);
                    break;
                }
                auto cert_name = std::string(reinterpret_cast<const char*>(raw_cert_name),
                                             strlen(reinterpret_cast<const char*>(raw_cert_name)));
                // Add to the final list of alternate names
                sans.emplace(cert_name);
                OPENSSL_free(raw_cert_name);
                break;
            }
        }
    }
    return sans;
}

bool SSLKeypairCertificate::add_extension(X509* certificate, int nid, const std::string& value)
{
    X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, nullptr, nid, value.c_str());
    if (!ex)
    {
        return false;
    }

    int result = X509_add_ext(certificate, ex, -1);

    X509_EXTENSION_free(ex);

    return result == 0;
}

bool SSLKeypairCertificate::add_certificate_extension(int nid, const std::string& value)
{
    return SSLKeypairCertificate::add_extension(certificate_, nid, value);
}

std::string SSLKeypairCertificate::get_certificate_extension(int nid)
{
    return SSLKeypairCertificate::get_extension(certificate_, nid);
}

bool SSLKeypairCertificate::delete_certificate_extension(int nid)
{
    return SSLKeypairCertificate::delete_extension(certificate_, nid);
}

std::unique_ptr<SSLKeypairCertificate> SSLKeypairCertificate::load_certificate(encryption::SecureStringUniquePtr data,
                                                                               const std::string& identifier)
{
    auto bio = std::unique_ptr<BIO, std::function<void(BIO*)>>(BIO_new(BIO_s_mem()), [](BIO* bio) { BIO_free(bio); });

    if (!BIO_puts(bio.get(), data->get().data()))
    {
        throw std::runtime_error("Could not write certificate to bio");
    }

    auto ssl_certificate = std::make_unique<SSLKeypairCertificate>(nullptr, true, identifier);
    ssl_certificate->certificate_ = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!ssl_certificate->certificate_)
    {
        throw std::runtime_error("Could not load PEM certificate");
    }

    return std::move(ssl_certificate);
}

bool SSLKeypairCertificate::compare_certificates(const SSLKeypairCertificate* cert1, const SSLKeypairCertificate* cert2)
{
    return cert1 != nullptr && cert2 != nullptr && X509_cmp(cert1->certificate_, cert2->certificate_) == 0 &&
           X509_subject_name_cmp(cert1->certificate_, cert2->certificate_) == 0 &&
           X509_issuer_name_cmp(cert1->certificate_, cert2->certificate_) == 0;
}

bool SSLKeypairCertificate::operator==(const SSLKeypairCertificate& other) const
{
    return SSLKeypairCertificate::compare_certificates(this, &other);
}

std::string SSLKeypairCertificate::get_extension(X509* certificate, int nid)
{
    char* buf = nullptr;
    BUF_MEM* bptr = nullptr;
    int loc = X509_get_ext_by_NID(certificate, nid, -1);
    if (loc == -1)
    {
        return "";
    }
    X509_EXTENSION* ex = X509_get_ext(certificate, loc);
    auto bio =
        std::unique_ptr<BIO, std::function<void(BIO*)>>(BIO_new(BIO_s_mem()), [](BIO* bio) { BIO_free_all(bio); });
    if (!X509V3_EXT_print(bio.get(), ex, 0, 0))
    {
        return "";
    }
    BIO_flush(bio.get());
    BIO_get_mem_ptr(bio.get(), &bptr);
    buf = static_cast<char*>(malloc((bptr->length + 1) * sizeof(char)));
    std::memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    std::string value = buf;
    free(buf);

    return value;
}

bool SSLKeypairCertificate::delete_extension(X509* certificate, int nid)
{
    int loc = X509_get_ext_by_NID(certificate, nid, -1);
    if (loc != -1)
    {
        X509_delete_ext(certificate, loc);
        return true;
    }
    return false;
}

X509* SSLKeypairCertificate::ssl_certificate() const
{
    return certificate_;
}

bool SSLKeypairCertificate::ssl_cert_ownership() const
{
    return cert_ownership_;
}

std::string SSLKeypairCertificate::identifier() const
{
    return identifier_;
}
} // namespace octo::keygen::ssl

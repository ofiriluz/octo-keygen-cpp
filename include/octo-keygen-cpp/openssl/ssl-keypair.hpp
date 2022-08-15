/**
 * @file ssl-keypair.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SSL_KEYPAIR_HPP_
#define SSL_KEYPAIR_HPP_

#include "octo-keygen-cpp/keypair.hpp"

typedef struct evp_pkey_st EVP_PKEY;
typedef struct rsa_st RSA;

namespace octo::keygen::ssl
{
static constexpr const char SSLKEYPAIR_TAG[] = "SSLKeypair";
class SSLKeypair : public Keypair
{
  private:
    int bits_amount_;

  protected:
    EVP_PKEY* private_key_;
    RSA* rsa_key_;

  public:
    SSLKeypair(int bits_amount);
    ~SSLKeypair() override;

    [[nodiscard]] std::string public_key() const override;
    [[nodiscard]] std::string private_key(const std::string& passphrase = "") const override;
    [[nodiscard]] std::string key_pair_type() const override;

    friend class SSLKeygen;
};
typedef std::shared_ptr<SSLKeypair> SSLKeypairPtr;
} // namespace octo::keygen::ssl

#endif
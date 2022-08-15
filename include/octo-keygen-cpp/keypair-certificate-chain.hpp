/**
 * @file keypair-certificate-chain.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KEYPAIR_CERTIFICATE_CHAIN_HPP_
#define KEYPAIR_CERTIFICATE_CHAIN_HPP_

#include <memory>
#include <string>
#include <vector>

namespace octo::keygen
{
class KeypairCertificateChain
{
  public:
    KeypairCertificateChain() = default;
    virtual ~KeypairCertificateChain() = default;

    [[nodiscard]] virtual std::vector<std::string> certificate_chain() const = 0;
};
typedef std::shared_ptr<KeypairCertificateChain> KeypairCertificateChainPtr;
} // namespace octo::keygen

#endif

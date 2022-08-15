/**
 * @file keypair-certificate.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KEYPAIR_CERTIFICATE_HPP_
#define KEYPAIR_CERTIFICATE_HPP_

#include <memory>
#include <string>
#include "keypair.hpp"

namespace octo::keygen
{
class KeypairCertificate
{
  public:
    KeypairCertificate() = default;
    virtual ~KeypairCertificate() = default;

    [[nodiscard]] virtual std::string certificate() const = 0;
    [[nodiscard]] virtual std::string certificate_type() const = 0;
    [[nodiscard]] virtual std::string pretty_print_certificate_info() const = 0;
};
typedef std::shared_ptr<KeypairCertificate> KeypairCertificatePtr;
} // namespace octo::keygen

#endif
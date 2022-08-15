/**
 * @file keygen.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KEYGEN_HPP_
#define KEYGEN_HPP_

#include "keygen-options.hpp"
#include "keypair.hpp"
#include "keypair-certificate.hpp"

namespace octo::keygen
{
class Keygen
{
  public:
    Keygen() = default;
    virtual ~Keygen() = default;

    [[nodiscard]] virtual KeypairPtr generate_keypair(const KeygenOptions& options) = 0;
    [[nodiscard]] virtual KeypairCertificatePtr sign_key_pair_with_ca(const KeypairPtr& key_pair,
                                                                      const std::string& ca,
                                                                      const KeygenOptions& sign_options) = 0;
    [[nodiscard]] virtual KeypairCertificatePtr sign_key_pair(const KeypairPtr& key_pair,
                                                              const KeygenOptions& sign_options) = 0;
};
typedef std::shared_ptr<Keygen> KeygenPtr;
} // namespace octo::keygen

#endif
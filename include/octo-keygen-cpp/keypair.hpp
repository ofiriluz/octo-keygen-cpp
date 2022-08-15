/**
 * @file keypair.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KEYPAIR_HPP_
#define KEYPAIR_HPP_

#include <memory>
#include <string>

namespace octo::keygen
{
class Keypair
{
  public:
    Keypair() = default;
    virtual ~Keypair() = default;

    [[nodiscard]] virtual std::string public_key() const = 0;
    [[nodiscard]] virtual std::string private_key(const std::string& passphrase = "") const = 0;
    [[nodiscard]] virtual std::string key_pair_type() const = 0;
};
typedef std::shared_ptr<Keypair> KeypairPtr;
} // namespace octo::keygen

#endif
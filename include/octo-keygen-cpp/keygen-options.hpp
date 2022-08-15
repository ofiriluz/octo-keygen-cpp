/**
 * @file keygen-options.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef KEYGEN_OPTIONS_HPP_
#define KEYGEN_OPTIONS_HPP_

#include <map>
#include <string>
#include <exception>

namespace octo::keygen
{
class KeygenOptions
{
  private:
    std::map<std::string, std::string> options_;

  public:
    KeygenOptions() = default;
    virtual ~KeygenOptions() = default;
    void set_option(const std::string& key, const std::string& value);
    void allow_option(const std::string& key);
    [[nodiscard]] std::string option(const std::string& key) const;
    [[nodiscard]] bool has_option(const std::string& key) const;
    void clear_options();
    [[nodiscard]] std::string format_options() const;
};
} // namespace octo::keygen

#endif
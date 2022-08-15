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

#include "octo-keygen-cpp/keygen-options.hpp"
#include <sstream>

namespace octo::keygen
{
void KeygenOptions::set_option(const std::string& key, const std::string& value)
{
    options_[key] = value;
}

void KeygenOptions::allow_option(const std::string& key)
{
    options_[key] = "";
}

std::string KeygenOptions::option(const std::string& key) const
{
    if (has_option(key))
    {
        return options_.at(key);
    }

    throw std::runtime_error("Option not found");
}

bool KeygenOptions::has_option(const std::string& key) const
{
    return options_.find(key) != options_.end();
}

void KeygenOptions::clear_options()
{
    options_.clear();
}

std::string KeygenOptions::format_options() const
{
    std::stringstream ss;
    for (auto& opt : options_)
    {
        ss << opt.first << "=" << opt.second << std::endl;
    }

    return ss.str();
}
} // namespace octo::keygen

// Copyright(c) 2015-present, Gabi Melman & spdlog contributors.
// Distributed under the MIT License (http://opensource.org/licenses/MIT)

#pragma once

#include <spdlog/common.h>
#include <spdlog/pattern_formatter.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <regex>
#include <string>
#include <vector>

namespace spdlog {

// Data masker for sensitive information protection
// Supports masking of phone numbers, emails, ID cards, tokens, passwords, etc.
class SPDLOG_API data_masker {
public:
    data_masker() = default;

    // Add a custom masking rule
    data_masker &add_rule(const std::string &name, const std::string &regex_pattern,
                          std::function<std::string(const std::smatch &)> replacer) {
        rules_.emplace_back(name, regex_pattern, std::move(replacer));
        return *this;
    }

    // Add a simple masking rule that replaces matches with a fixed mask
    data_masker &add_rule(const std::string &name, const std::string &regex_pattern,
                          const std::string &mask) {
        rules_.emplace_back(name, regex_pattern, [mask](const std::smatch &) { return mask; });
        return *this;
    }

    // Add built-in rule for Chinese phone numbers (手机号)
    // Masks the middle 4 digits: 13812345678 -> 138****5678
    data_masker &add_phone_rule() {
        return add_rule("phone", R"(\b(1[3-9]\d)\d{4}(\d{4})\b)",
                        [](const std::smatch &m) { return m[1].str() + "****" + m[2].str(); });
    }

    // Add built-in rule for email addresses (邮箱)
    // Masks the username part: user@example.com -> u***@example.com
    data_masker &add_email_rule() {
        return add_rule(
            "email", R"(\b([a-zA-Z0-9._%+-])[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b)",
            [](const std::smatch &m) { return m[1].str() + "***@" + m[2].str(); });
    }

    // Add built-in rule for Chinese ID cards (身份证号)
    // Masks the middle part: 110101199001011234 -> 110101********1234
    data_masker &add_id_card_rule() {
        return add_rule("id_card", R"(\b(\d{6})\d{8}(\d{4})\b)",
                        [](const std::smatch &m) { return m[1].str() + "********" + m[2].str(); });
    }

    // Add built-in rule for bank card numbers (银行卡号)
    // Masks the middle digits: 6222021234567890123 -> 6222****0123
    data_masker &add_bank_card_rule() {
        return add_rule("bank_card", R"(\b(\d{4})\d{8,12}(\d{4})\b)",
                        [](const std::smatch &m) { return m[1].str() + "****" + m[2].str(); });
    }

    // Add built-in rule for passwords in common formats
    // Matches patterns like password=xxx, pwd=xxx, passwd: xxx
    data_masker &add_password_rule() {
        return add_rule("password", R"(((?:password|passwd|pwd)[\s]*[=:]\s*)(\S+))",
                        [](const std::smatch &m) { return m[1].str() + "******"; });
    }

    // Add built-in rule for tokens and API keys
    // Matches patterns like token=xxx, api_key=xxx, secret=xxx
    data_masker &add_token_rule() {
        return add_rule("token",
                        R"(((?:token|api_key|apikey|secret|access_token|auth)[\s]*[=:]\s*)(\S+))",
                        [](const std::smatch &m) { return m[1].str() + "******"; });
    }

    // Add all built-in rules
    data_masker &add_all_builtin_rules() {
        add_phone_rule();
        add_email_rule();
        add_id_card_rule();
        add_bank_card_rule();
        add_password_rule();
        add_token_rule();
        return *this;
    }

    // Apply all masking rules to the input string
    std::string mask(const std::string &input) const {
        if (rules_.empty()) {
            return input;
        }

        std::string result = input;
        for (const auto &rule : rules_) {
            result = apply_rule(result, rule);
        }
        return result;
    }

    // Apply masking to a string_view and return the masked string
    // Note: String conversion is required because std::regex only works with std::string
    std::string mask(string_view_t input) const {
        return mask(std::string(input.data(), input.size()));
    }

    // Overload for const char* to resolve ambiguity
    std::string mask(const char *input) const { return mask(std::string(input)); }

    // Clear all rules
    void clear_rules() { rules_.clear(); }

    // Get the number of rules
    size_t rule_count() const { return rules_.size(); }

    // Clone the masker (for thread safety in formatters)
    std::unique_ptr<data_masker> clone() const {
        auto cloned = details::make_unique<data_masker>();
        for (const auto &rule : rules_) {
            cloned->rules_.emplace_back(rule.name, rule.pattern_str, rule.replacer);
        }
        return cloned;
    }

private:
    // A masking rule with pattern and replacement function
    struct masking_rule {
        std::regex pattern;
        std::string pattern_str;
        std::function<std::string(const std::smatch &)> replacer;
        std::string name;  // for debugging/identification

        masking_rule(std::string rule_name, const std::string &regex_pattern,
                     std::function<std::string(const std::smatch &)> replace_func)
            : pattern(regex_pattern),
              pattern_str(regex_pattern),
              replacer(std::move(replace_func)),
              name(std::move(rule_name)) {}
    };

    std::string apply_rule(const std::string &input, const masking_rule &rule) const {
        std::string result;
        std::sregex_iterator it(input.begin(), input.end(), rule.pattern);
        std::sregex_iterator end;

        size_t last_pos = 0;
        for (; it != end; ++it) {
            const std::smatch &match = *it;
            result.append(input, last_pos, match.position() - last_pos);
            result.append(rule.replacer(match));
            last_pos = match.position() + match.length();
        }
        result.append(input, last_pos, input.size() - last_pos);
        return result;
    }

    std::vector<masking_rule> rules_;
};

// Custom flag formatter that masks sensitive data in log messages
// Usage: formatter->add_flag<masked_v_formatter>('*', masker).set_pattern("[%l] %*");
class SPDLOG_API masked_v_formatter : public custom_flag_formatter {
public:
    explicit masked_v_formatter(std::shared_ptr<data_masker> masker)
        : masker_(std::move(masker)) {}

    void format(const details::log_msg &msg, const std::tm &, memory_buf_t &dest) override {
        if (masker_) {
            std::string masked = masker_->mask(msg.payload);
            dest.append(masked.data(), masked.data() + masked.size());
        } else {
            // No masker, just append the original message
            auto *buf_ptr = msg.payload.data();
            dest.append(buf_ptr, buf_ptr + msg.payload.size());
        }
    }

    std::unique_ptr<custom_flag_formatter> clone() const override {
        // Share the masker (thread-safe for read operations)
        return details::make_unique<masked_v_formatter>(masker_);
    }

private:
    std::shared_ptr<data_masker> masker_;
};

// Helper function to create a pattern formatter with masking enabled
// The masked message will use the '*' flag instead of 'v'
// Note: '%*' is used for masked message (do not use '%M' as it conflicts with minutes)
inline std::unique_ptr<pattern_formatter> make_masked_formatter(
    std::shared_ptr<data_masker> masker,
    const std::string &pattern = "[%Y-%m-%d %H:%M:%S.%e] [%n] [%l] %*",
    pattern_time_type time_type = pattern_time_type::local) {
    auto formatter = details::make_unique<pattern_formatter>(time_type);
    formatter->add_flag<masked_v_formatter>('*', std::move(masker));
    formatter->set_pattern(pattern);
    return formatter;
}

}  // namespace spdlog

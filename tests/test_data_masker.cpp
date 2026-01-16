#include "includes.h"
#include "spdlog/data_masker.h"
#include "spdlog/sinks/ostream_sink.h"

using spdlog::data_masker;
using spdlog::masked_v_formatter;
using spdlog::memory_buf_t;

TEST_CASE("data_masker-phone", "[data_masker]") {
    data_masker masker;
    masker.add_phone_rule();

    // Standard Chinese phone numbers
    REQUIRE(masker.mask("phone: 13812345678") == "phone: 138****5678");
    REQUIRE(masker.mask("call me at 15987654321") == "call me at 159****4321");
    REQUIRE(masker.mask("my number is 17012345678") == "my number is 170****5678");

    // Multiple phone numbers in one message
    REQUIRE(masker.mask("13812345678 and 15987654321") == "138****5678 and 159****4321");

    // Not a valid phone (wrong prefix or length)
    REQUIRE(masker.mask("12345678901") == "12345678901");  // not starting with 1[3-9]
    REQUIRE(masker.mask("1381234567") == "1381234567");    // too short
}

TEST_CASE("data_masker-email", "[data_masker]") {
    data_masker masker;
    masker.add_email_rule();

    REQUIRE(masker.mask("email: user@example.com") == "email: u***@example.com");
    REQUIRE(masker.mask("contact john.doe@company.org") == "contact j***@company.org");
    REQUIRE(masker.mask("a@b.co") == "a***@b.co");

    // Multiple emails
    REQUIRE(masker.mask("user1@a.com and user2@b.org") == "u***@a.com and u***@b.org");
}

TEST_CASE("data_masker-id_card", "[data_masker]") {
    data_masker masker;
    masker.add_id_card_rule();

    // 18-digit Chinese ID card
    REQUIRE(masker.mask("id: 110101199001011234") == "id: 110101********1234");
    REQUIRE(masker.mask("身份证号：440106198802054567") == "身份证号：440106********4567");
}

TEST_CASE("data_masker-bank_card", "[data_masker]") {
    data_masker masker;
    masker.add_bank_card_rule();

    REQUIRE(masker.mask("card: 6222021234567890123") == "card: 6222****0123");
    REQUIRE(masker.mask("card: 622202123456789012") == "card: 6222****9012");
}

TEST_CASE("data_masker-password", "[data_masker]") {
    data_masker masker;
    masker.add_password_rule();

    REQUIRE(masker.mask("password=secret123") == "password=******");
    REQUIRE(masker.mask("pwd: mysecret") == "pwd: ******");
    REQUIRE(masker.mask("passwd = hidden") == "passwd = ******");
    // Note: The default password rule is case-sensitive (lowercase only)
    // Capital letters won't match
    REQUIRE(masker.mask("Password=Test123") == "Password=Test123");
}

TEST_CASE("data_masker-token", "[data_masker]") {
    data_masker masker;
    masker.add_token_rule();

    REQUIRE(masker.mask("token=abc123xyz") == "token=******");
    REQUIRE(masker.mask("api_key: sk-1234567890") == "api_key: ******");
    REQUIRE(masker.mask("secret=mysecretvalue") == "secret=******");
    REQUIRE(masker.mask("access_token=Bearer_xyz") == "access_token=******");
}

TEST_CASE("data_masker-jwt", "[data_masker]") {
    data_masker masker;
    masker.add_jwt_rule();

    // Standard JWT token
    std::string jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    std::string expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.******.******";
    REQUIRE(masker.mask(jwt) == expected);

    // JWT in a sentence
    REQUIRE(masker.mask("Bearer " + jwt) == "Bearer " + expected);
}

TEST_CASE("data_masker-custom_rule", "[data_masker]") {
    data_masker masker;

    // Add a custom rule to mask IP addresses
    masker.add_rule("ip_address", R"(\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.(\d{1,3})\b)",
                    [](const std::smatch &m) { return m[1].str() + ".***.***." + m[2].str(); });

    REQUIRE(masker.mask("IP: 192.168.1.100") == "IP: 192.***.***.100");

    // Add a custom rule with fixed mask
    masker.add_rule("credit_card", R"(\b\d{4}-\d{4}-\d{4}-\d{4}\b)", "[MASKED-CARD]");
    REQUIRE(masker.mask("card: 1234-5678-9012-3456") == "card: [MASKED-CARD]");
}

TEST_CASE("data_masker-all_builtin_rules", "[data_masker]") {
    data_masker masker;
    masker.add_all_builtin_rules();

    std::string input = "User 13812345678 with email user@example.com and password=secret123";
    std::string expected = "User 138****5678 with email u***@example.com and password=******";
    REQUIRE(masker.mask(input) == expected);
}

TEST_CASE("data_masker-no_rules", "[data_masker]") {
    data_masker masker;
    std::string input = "No sensitive data here";
    REQUIRE(masker.mask(input) == input);
}

TEST_CASE("data_masker-empty_input", "[data_masker]") {
    data_masker masker;
    masker.add_phone_rule();
    REQUIRE(masker.mask("") == "");
}

TEST_CASE("data_masker-clone", "[data_masker]") {
    data_masker masker;
    masker.add_phone_rule();
    masker.add_email_rule();

    auto cloned = masker.clone();
    REQUIRE(cloned->rule_count() == 2);
    REQUIRE(cloned->mask("13812345678") == "138****5678");
    REQUIRE(cloned->mask("user@example.com") == "u***@example.com");
}

TEST_CASE("data_masker-clear_rules", "[data_masker]") {
    data_masker masker;
    masker.add_phone_rule();
    REQUIRE(masker.rule_count() == 1);
    masker.clear_rules();
    REQUIRE(masker.rule_count() == 0);
    REQUIRE(masker.mask("13812345678") == "13812345678");  // No masking
}

TEST_CASE("masked_v_formatter-basic", "[data_masker]") {
    auto masker = std::make_shared<data_masker>();
    masker->add_phone_rule();
    masker->add_email_rule();

    auto formatter = std::make_unique<spdlog::pattern_formatter>();
    formatter->add_flag<masked_v_formatter>('*', masker);
    formatter->set_pattern("%*");

    std::string logger_name = "test";
    spdlog::details::log_msg msg(logger_name, spdlog::level::info,
                                 "Call 13812345678 or email user@example.com");

    memory_buf_t formatted;
    formatter->format(msg, formatted);

    std::string result(formatted.data(), formatted.size());
    // Remove the end-of-line added by formatter
    auto eol = spdlog::details::os::default_eol;
    if (result.size() >= strlen(eol) &&
        result.substr(result.size() - strlen(eol)) == eol) {
        result = result.substr(0, result.size() - strlen(eol));
    }

    REQUIRE(result == "Call 138****5678 or email u***@example.com");
}

TEST_CASE("masked_v_formatter-clone", "[data_masker]") {
    auto masker = std::make_shared<data_masker>();
    masker->add_phone_rule();

    auto formatter1 = std::make_shared<spdlog::pattern_formatter>();
    formatter1->add_flag<masked_v_formatter>('*', masker);
    formatter1->set_pattern("%*");

    auto formatter2 = formatter1->clone();

    std::string logger_name = "test";
    spdlog::details::log_msg msg(logger_name, spdlog::level::info, "Phone: 13812345678");

    memory_buf_t formatted1, formatted2;
    formatter1->format(msg, formatted1);
    formatter2->format(msg, formatted2);

    REQUIRE(spdlog::details::to_string_view(formatted1) ==
            spdlog::details::to_string_view(formatted2));
}

TEST_CASE("make_masked_formatter", "[data_masker]") {
    auto masker = std::make_shared<data_masker>();
    masker->add_phone_rule();

    auto formatter = spdlog::make_masked_formatter(masker, "%*");

    std::string logger_name = "test";
    spdlog::details::log_msg msg(logger_name, spdlog::level::info, "Number: 13812345678");

    memory_buf_t formatted;
    formatter->format(msg, formatted);

    std::string result(formatted.data(), formatted.size());
    auto eol = spdlog::details::os::default_eol;
    if (result.size() >= strlen(eol) &&
        result.substr(result.size() - strlen(eol)) == eol) {
        result = result.substr(0, result.size() - strlen(eol));
    }

    REQUIRE(result == "Number: 138****5678");
}

TEST_CASE("masked_formatter-with_logger", "[data_masker]") {
    std::ostringstream oss;
    auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(oss);

    auto masker = std::make_shared<data_masker>();
    masker->add_phone_rule();
    masker->add_password_rule();

    auto formatter = spdlog::make_masked_formatter(masker, "%*");
    sink->set_formatter(std::move(formatter));

    auto logger = std::make_shared<spdlog::logger>("test_logger", sink);
    logger->set_level(spdlog::level::info);

    logger->info("User phone: 13812345678, password=secret123");
    logger->flush();

    std::string output = oss.str();
    REQUIRE(output.find("138****5678") != std::string::npos);
    REQUIRE(output.find("password=******") != std::string::npos);
    REQUIRE(output.find("13812345678") == std::string::npos);
    REQUIRE(output.find("secret123") == std::string::npos);
}

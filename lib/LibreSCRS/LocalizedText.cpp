// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/LocalizedText.h>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace LibreSCRS {

namespace {

// Compile-time guard: Placeholder::Type and the std::variant alternatives
// of Placeholder::value are documented to align by index. If anyone adds
// a new Type enumerator without extending the variant (or vice versa),
// or reorders one of the two without the other, these asserts catch the
// drift at build time. Per-alternative checks subsume the size check.
using PlaceholderVariant = decltype(Placeholder::value);
static_assert(std::variant_size_v<PlaceholderVariant> == static_cast<std::size_t>(Placeholder::Type::Bool) + 1,
              "Placeholder::Type and Placeholder::value variant alternatives drifted; "
              "add the missing alternative or enumerator.");
static_assert(
    std::is_same_v<std::variant_alternative_t<static_cast<std::size_t>(Placeholder::Type::String), PlaceholderVariant>,
                   std::string>);
static_assert(
    std::is_same_v<std::variant_alternative_t<static_cast<std::size_t>(Placeholder::Type::Int), PlaceholderVariant>,
                   std::int64_t>);
static_assert(
    std::is_same_v<std::variant_alternative_t<static_cast<std::size_t>(Placeholder::Type::UInt), PlaceholderVariant>,
                   std::uint64_t>);
static_assert(
    std::is_same_v<std::variant_alternative_t<static_cast<std::size_t>(Placeholder::Type::Hex), PlaceholderVariant>,
                   std::vector<std::uint8_t>>);
static_assert(
    std::is_same_v<std::variant_alternative_t<static_cast<std::size_t>(Placeholder::Type::Date), PlaceholderVariant>,
                   std::chrono::system_clock::time_point>);
static_assert(
    std::is_same_v<std::variant_alternative_t<static_cast<std::size_t>(Placeholder::Type::Count), PlaceholderVariant>,
                   Count>);
static_assert(std::is_same_v<
              std::variant_alternative_t<static_cast<std::size_t>(Placeholder::Type::Bool), PlaceholderVariant>, bool>);

std::string formatHex(std::span<const std::uint8_t> bytes)
{
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02X", b);
        out.append(buf, 2);
    }
    return out;
}

std::string formatTime(std::chrono::system_clock::time_point tp)
{
    auto t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    if (!gmtime_r(&t, &tm))
        return {};
    char buf[32]{};
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
        return {};
    return buf;
}

} // namespace

std::string Placeholder::formatted() const
{
    return std::visit(
        [](const auto& v) -> std::string {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, std::string>) {
                return v;
            } else if constexpr (std::is_same_v<T, std::int64_t>) {
                return std::to_string(v);
            } else if constexpr (std::is_same_v<T, Count>) {
                return std::to_string(v.value);
            } else if constexpr (std::is_same_v<T, std::uint64_t>) {
                return std::to_string(v);
            } else if constexpr (std::is_same_v<T, std::vector<std::uint8_t>>) {
                return formatHex({v.data(), v.size()});
            } else if constexpr (std::is_same_v<T, std::chrono::system_clock::time_point>) {
                return formatTime(v);
            } else if constexpr (std::is_same_v<T, bool>) {
                return v ? "true" : "false";
            } else {
                return {};
            }
        },
        value);
}

std::string_view LocalizedText::domain() const noexcept
{
    auto pos = key.find('.');
    if (pos == std::string::npos) {
        return std::string_view{key.data(), key.size()};
    }
    return std::string_view{key.data(), pos};
}

std::string LocalizedText::interpolate(std::string_view format) const
{
    std::string out;
    out.reserve(format.size() + 32);

    for (std::size_t i = 0; i < format.size();) {
        if (i + 1 < format.size() && format[i] == '{' && format[i + 1] == '{') {
            out.push_back('{');
            i += 2;
            continue;
        }
        if (i + 1 < format.size() && format[i] == '}' && format[i + 1] == '}') {
            out.push_back('}');
            i += 2;
            continue;
        }
        if (format[i] != '{') {
            out.push_back(format[i]);
            ++i;
            continue;
        }
        auto close = format.find('}', i + 1);
        if (close == std::string_view::npos) {
            out.append(format.substr(i));
            break;
        }
        const auto name = format.substr(i + 1, close - i - 1);
        const Placeholder* matched = nullptr;
        for (const auto& ph : placeholders) {
            if (std::string_view{ph.name} == name) {
                matched = &ph;
                break;
            }
        }
        if (matched) {
            out.append(matched->formatted());
        } else {
            out.append(format.substr(i, close - i + 1));
        }
        i = close + 1;
    }
    return out;
}

} // namespace LibreSCRS

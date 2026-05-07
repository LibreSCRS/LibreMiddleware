// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#pragma once

/// @file
/// @brief @ref LibreSCRS::Plugin::AutoReaderService — active plugin-dispatch
///        worker that pairs @ref LibreSCRS::SmartCard::MonitorService events with
///        @ref LibreSCRS::Plugin::CardPluginService lookups and hands
///        readable @ref LibreSCRS::Plugin::CardData back to the host via
///        its @c OnCardData / @c OnError callback seams.

#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/Plugin/CardData.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace LibreSCRS::SmartCard {
class MonitorService;
struct MonitorEvent;
} // namespace LibreSCRS::SmartCard

namespace LibreSCRS::Plugin {

class CardPluginService;

/// @brief Bridges a @ref LibreSCRS::SmartCard::MonitorService with a @ref CardPluginService
///        to automatically dispatch card reads on insert events.
///
/// Subscribes to the monitor on construction; on each insert event, selects a
/// plugin from the registry and launches an asynchronous read. Results are
/// delivered via @ref OnCardData; errors via @ref OnError when set.
///
/// @note Non-copyable, non-movable. Outstanding reads are cancelled on destruction.
///
/// @par Thread-safety
/// Thread-safe (see API-POLICY §8). Public methods (@ref isReading) may be
/// called concurrently — internal bookkeeping is guarded by an internal
/// mutex. The @ref OnCardData / @ref OnError callbacks fire on AutoReaderService's
/// worker thread (see "Callback thread" paragraph below); consumers
/// integrating with a GUI toolkit MUST marshal back to the UI thread.
///
/// @par Ownership policy
/// Per the project-wide API convention ("all public LibreSCRS services take
/// `shared_ptr` for their dependencies"), the @ref LibreSCRS::SmartCard::MonitorService
/// and @ref CardPluginService arguments are taken by `std::shared_ptr`. The
/// worker captures a `std::weak_ptr` into the monitor-subscription lambda
/// and promotes it at callback time, so any destruction order of the
/// consumer's monitor / registry / reader triple is safe — the previous
/// "must outlive" contract is gone. Peer service
/// @ref LibreSCRS::Signing::SigningService::sign follows the same pattern
/// for its @c cardPlugin and @c session parameters.
///
/// @par Callback thread
/// The @ref OnCardData and @ref OnError callbacks fire on AutoReaderService's
/// internal worker thread (not on the MonitorService poll thread). Consumers
/// integrating with a GUI toolkit MUST marshal the callback into the
/// UI thread using the toolkit's own dispatch primitive (e.g.
/// `QMetaObject::invokeMethod` with `Qt::QueuedConnection`, GLib's
/// `g_idle_add`). Blocking the callback thread delays subsequent
/// card events — keep the callback body short.
class LIBRESCRS_PUBLIC_API AutoReaderService
{
public:
    /// @brief Structured error delivered to the @ref OnError callback.
    ///
    /// Replaces the earlier free-form `std::string` so hosts can switch on a
    /// known set of failure modes, carry a translator-friendly user-facing
    /// message, and keep a separate diagnostic detail for logs.
    struct AutoReaderError
    {
        /// @brief Failure-mode classification.
        ///
        /// @note Append-only per API-POLICY §4 (consumer-facing error enums).
        ///       New variants are added at the end of the enumeration; existing
        ///       discriminator values are stable across minor / patch releases.
        enum class Kind : std::uint8_t {
            CardReadFailed,     ///< All candidate plugins failed to read the card.
            PluginError,        ///< Selected plugin threw / reported an internal error.
            PreReadAuthFailed,  ///< Pre-read authentication (BAC/PACE) failed.
            ReaderDisconnected, ///< Reader connection lost mid-read.
            RegistryEmpty,      ///< @since 4.0. The CardPluginService is empty or has only failed plugins
                                ///< (per @ref CardPluginService::isUsable). The card-insert event was
                                ///< received but no plugin could be probed; surfaces an actionable
                                ///< "no plugins installed" message rather than the ambiguous
                                ///< "no plugin matched this card" code path.
        };

        /// @brief Classification of the failure.
        Kind kind = Kind::CardReadFailed;
        /// @brief Translator-friendly user-facing message. Mandatory in 4.0;
        ///        callers without a card-specific message use one of the
        ///        @ref LibreSCRS::Auth::ErrorKeys builders (e.g.
        ///        @ref Auth::ErrorKeys::registryEmpty,
        ///        @ref Auth::ErrorKeys::cardReadFailed).
        /// @since 4.0 — was @c std::optional<LocalizedText> in 3.x.
        LocalizedText userMessage;
        /// @brief Optional technical detail suitable for logs.
        std::optional<std::string> diagnosticDetail;
    };

    /// @brief Callback delivering a completed @ref CardData read for a named reader.
    using OnCardData = std::function<void(const std::string& readerName, const CardData& data)>;

    /// @brief Callback delivering a structured @ref AutoReaderError for a named reader.
    using OnError = std::function<void(const std::string& readerName, const AutoReaderError& error)>;

    /// @brief Construct and subscribe to @p monitor for card events.
    /// @param monitor Shared-ownership pointer to the SmartCard monitor.
    ///                AutoReaderService's subscribe lambda captures a `weak_ptr`
    ///                into its worker, so monitor destruction — even
    ///                mid-callback — is safe.
    /// @param registry Shared-ownership pointer to the plugin registry.
    ///                 Consulted on each card insert; captured by the worker
    ///                 and held alive for the duration of any in-flight read.
    /// @param onData Required callback invoked on successful reads.
    /// @param onError Optional callback invoked on errors; may be null.
    ///
    /// @note Takes shared ownership to eliminate destruction-order
    ///       dependencies ("UAF-on-shutdown class"). Consumers pass their
    ///       application-level `shared_ptr`s; the worker thread promotes
    ///       `weak_ptr` on invocation.
    AutoReaderService(std::shared_ptr<LibreSCRS::SmartCard::MonitorService> monitor,
                      std::shared_ptr<CardPluginService> registry, OnCardData onData, OnError onError = nullptr);
    /// @brief Unsubscribes from the monitor and cancels in-flight reads.
    ~AutoReaderService();

    AutoReaderService(const AutoReaderService&) = delete;
    AutoReaderService& operator=(const AutoReaderService&) = delete;
    // Non-movable: the monitor subscription is installed at construction and
    // refers to the worker instance captured by weak_ptr. Keeping the type
    // non-movable avoids any subtle ambiguity over subscription transfer
    // semantics; if a future caller needs move semantics, wrap in a
    // `unique_ptr<AutoReaderService>`.
    AutoReaderService(AutoReaderService&&) = delete;
    AutoReaderService& operator=(AutoReaderService&&) = delete;

    /// @brief True when an asynchronous read for @p readerName is currently
    ///        in flight.
    ///
    /// The worker tracks the set of readers with active read jobs. Consumers
    /// use this to drive a "reading…" indicator in the UI without racing
    /// against the read's completion callback. The call is a point-in-time
    /// snapshot: a read that is about to start but has not yet marked itself
    /// active will return @c false; a read that has already fired its
    /// completion callback (but whose bookkeeping entry has not yet been
    /// cleared) may briefly return @c true. UIs that need strict ordering
    /// should drive state from the completion callback, not from polling
    /// this accessor.
    ///
    /// @param readerName Reader whose in-flight state to query. Looked up
    ///                   exactly (no substring / case-insensitive match).
    ///                   A reader name that AutoReaderService has never seen
    ///                   returns @c false.
    /// @return @c true if a read for @p readerName is active right now.
    /// @note @c noexcept — the internal worker state is guarded by a mutex;
    ///       the lock-and-lookup path cannot throw.
    /// @since 4.0.
    [[nodiscard]] bool isReading(std::string_view readerName) const noexcept;

private:
    struct Impl;
    // Unique ownership. Non-copyable / non-movable (via deleted ops above)
    // matches the consumer contract. The subscribe lambda captures a
    // `weak_ptr` to the internal (anonymous-namespace) worker state — not
    // to `Impl` — so a late dispatch after ~AutoReaderService becomes a safe
    // no-op instead of a use-after-free, without leaking any `::Impl`
    // symbol through std-template weak-symbol instantiations.
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Plugin

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Signing::VisualSignatureParams — PAdES visual
///        signature appearance bundle (and its @ref LibreSCRS::Signing::Rect
///        geometry helper + @ref LibreSCRS::Signing::kDefaultVisualSignatureRect
///        default).

#include <LibreSCRS/Export.h>

#include <memory>
#include <string>

namespace LibreSCRS::Signing {

/// @brief Rectangular region (PDF user units) for a signature annotation.
///
/// @note Members are `int` because PDF user units are integer PDF coordinate
///       quantities at the API boundary; the renderer handles fractional
///       coordinate math internally.
struct Rect
{
    int x = 0;      ///< Left coordinate in PDF user space; may be negative.
    int y = 0;      ///< Bottom coordinate in PDF user space; may be negative.
    int width = 0;  ///< Width; must be positive when passed to @ref VisualSignatureParams::Builder::rect.
    int height = 0; ///< Height; must be positive when passed to @ref VisualSignatureParams::Builder::rect.
};

/// @brief Default annotation rectangle used when no explicit
///        @ref LibreSCRS::Signing::VisualSignatureParams::Builder::rect call is made.
///
/// 200x50 at the origin (0,0) — a widely compatible bottom-left placement.
/// Exposed so host code and tests can reference "the default" by name
/// instead of duplicating the numeric literal.
/// @since 4.0
inline constexpr Rect kDefaultVisualSignatureRect{0, 0, 200, 50};

/// @brief Visual-appearance parameters for a PAdES signature annotation.
///
/// Opaque pimpl, value-semantic (copyable and movable), PAdES-only.
/// Constructed via @ref Builder, which validates its inputs before returning
/// the immutable value.
///
/// @note Attempting to attach a @ref VisualSignatureParams to a non-PAdES
///       request causes @ref SigningRequest::Builder::build to throw
///       `std::invalid_argument`.
/// @note Copy is trivially cheap — deep-copies the small-data pimpl
///       (geometry ints + a text template string). Enables
///       @ref SigningRequest::visualParams to return by value without
///       exposing caller-invalidation footguns.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). @ref VisualSignatureParams is
/// immutable after `Builder::build()` returns: the pimpl holds plain data
/// (ints + text template) with no internal synchronisation. Distinct
/// instances are independent; concurrent reads of the same instance are
/// race-free. The Builder itself is single-threaded relative to its own
/// instance.
///
/// @since 4.0
class LIBRESCRS_PUBLIC_API VisualSignatureParams
{
public:
    class Builder;

    /// @brief Move-construct from @p other.
    VisualSignatureParams(VisualSignatureParams&&) noexcept;
    /// @brief Move-assign from @p other.
    VisualSignatureParams& operator=(VisualSignatureParams&&) noexcept;
    /// @brief Copy-construct by deep-copying the pimpl.
    VisualSignatureParams(const VisualSignatureParams&);
    /// @brief Copy-assign by deep-copying the pimpl.
    VisualSignatureParams& operator=(const VisualSignatureParams&);
    ~VisualSignatureParams();

    /// @brief True when this object holds a valid (non-moved-from) pimpl.
    ///
    /// Mirrors the moved-from check on sibling pimpl-backed types
    /// (@ref SigningRequest, @ref LibreSCRS::Signing::SigningService,
    /// @ref LibreSCRS::SmartCard::CardSession). `if (!params)` is always
    /// well-defined; accessors on a moved-from instance are undefined
    /// behaviour.
    /// @since 4.0
    explicit operator bool() const noexcept
    {
        return d != nullptr;
    }

    /// @brief Zero-based index of the page on which to draw the annotation.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] int pageIndex() const noexcept;
    /// @brief X coordinate of the annotation rectangle (PDF user units).
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] int x() const noexcept;
    /// @brief Y coordinate of the annotation rectangle (PDF user units).
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] int y() const noexcept;
    /// @brief Width of the annotation rectangle (PDF user units).
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] int width() const noexcept;
    /// @brief Height of the annotation rectangle (PDF user units).
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] int height() const noexcept;
    /// @brief Text template (may contain `{placeholder}` tokens resolved by the engine).
    /// @note Returned reference is valid while this object is alive.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3.
    [[nodiscard]] const std::string& textTemplate() const noexcept;

private:
    friend class Builder;
    VisualSignatureParams();
    struct Impl;
    std::unique_ptr<Impl> d;
};

/// @brief Fluent builder that validates and produces a @ref VisualSignatureParams.
///
/// Setters return a reference to the builder. @ref build is rvalue-qualified —
/// use `std::move(builder).build()` on a named builder instance.
///
/// @par Validation policy
/// Each setter validates its argument eagerly and throws
/// @c std::invalid_argument on the spot; @ref build is @c noexcept and cannot
/// fail. @ref VisualSignatureParams has no cross-field invariants (every
/// field is independent), so a "validate at @c build" shape would add
/// complexity without catching any additional errors. Contrast with
/// @ref SigningRequest::Builder, which validates inside @ref
/// SigningRequest::Builder::build because its invariants span multiple
/// fields (e.g. `visualParams` requires `format == PAdES`) and cannot be
/// checked until the full set of values is present. Per API-POLICY §5.1,
/// validation that CAN be enforced at setter time IS enforced at setter
/// time.
class LIBRESCRS_PUBLIC_API VisualSignatureParams::Builder
{
public:
    Builder();
    ~Builder();
    /// @brief Move-construct the builder.
    Builder(Builder&&) noexcept;
    /// @brief Move-assign the builder.
    Builder& operator=(Builder&&) noexcept;

    /// @brief Set the zero-based page index.
    /// @param idx Zero-based page index; must be non-negative.
    /// @throws std::invalid_argument if @p idx is negative. See API-POLICY §5.1.
    Builder& pageIndex(int idx);
    /// @brief Set the annotation rectangle.
    /// @param r Rectangle geometry. @c x / @c y may be negative (off-page);
    ///          @c width / @c height must be positive.
    /// @throws std::invalid_argument if @p r.width or @p r.height is not
    ///         positive. See API-POLICY §5.1.
    Builder& rect(const Rect& r);
    /// @brief Set the text template rendered inside the annotation.
    /// @note Accepts any string including empty. Placeholder syntax is validated
    ///       by the rendering engine at sign time, not here.
    Builder& textTemplate(std::string tmpl);

    /// @brief Consume the builder and produce an immutable VisualSignatureParams.
    /// @return Configured VisualSignatureParams (move-only, never empty).
    /// @note Assembly-only. All invariants are enforced at setter-invocation
    ///       time by @ref pageIndex and @ref rect; defaults (pageIndex=0,
    ///       200x50 rect at origin) are independently valid, so there are no
    ///       cross-setter invariants left to check here. Per API-POLICY §5.1,
    ///       validation that CAN be enforced at the setter level IS enforced
    ///       there, making this call infallible.
    [[nodiscard]] VisualSignatureParams build() && noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Signing

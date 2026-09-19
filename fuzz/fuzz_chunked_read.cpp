// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// libFuzzer harness for LibreSCRS::SmartCard::Internal::readChunkedFile.
//
// Every card-file read in this library goes through this helper, and the file
// length it allocates for is read out of the file header -- card-controlled
// bytes that arrive before anything has authenticated the card. The input to
// this harness is therefore the card image: the bytes a chip serves for each
// READ BINARY, header first.
//
// The harness drives the three option shapes the shipped readers use: a
// fixed-offset header spec with an empty-file marker, a plain fixed-offset
// spec, and a caller-supplied header parser. The last one is the interesting
// case, because a caller-supplied parser is free to return any length at all.
//
// Build: -DLIBRESCRS_BUILD_FUZZ=ON.
// Run:   ./fuzz_chunked_read -max_total_time=60 corpus/chunked_read

// LIBRESCRS_INTERNAL_BUILD is set via target_compile_definitions in CMake.
#include "apdu.h"
#include <smartcard/chunked_read.h>
#include <smartcard/i_connection.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <vector>

namespace {

namespace SC = LibreSCRS::SmartCard::Internal;

/// Serves READ BINARY out of a flat card image. Anything past the end comes
/// back as a successful empty read, which is how a real card signals EOF and
/// how the read loop is expected to stop.
class ImageConnection final : public LibreSCRS::SmartCard::IConnection
{
public:
    explicit ImageConnection(std::span<const std::uint8_t> image) : image(image) {}

    SC::APDUResponse transmit(const SC::APDUCommand& cmd) override
    {
        SC::APDUResponse resp;
        resp.sw1 = 0x90;
        resp.sw2 = 0x00;
        ++reads;
        const std::size_t offset = (static_cast<std::size_t>(cmd.p1) << 8) | cmd.p2;
        if (offset >= image.size()) {
            return resp;
        }
        const std::size_t want = cmd.le == 0 ? 256u : cmd.le;
        const std::size_t have = std::min(want, image.size() - offset);
        resp.data.assign(image.begin() + static_cast<std::ptrdiff_t>(offset),
                         image.begin() + static_cast<std::ptrdiff_t>(offset + have));
        return resp;
    }

    SC::APDUResponse transmitRaw(std::span<const std::uint8_t> cmdBytes) override
    {
        SC::APDUCommand cmd{};
        if (cmdBytes.size() >= 4) {
            cmd.cla = cmdBytes[0];
            cmd.ins = cmdBytes[1];
            cmd.p1 = cmdBytes[2];
            cmd.p2 = cmdBytes[3];
        }
        return transmit(cmd);
    }

    std::size_t reads = 0;

private:
    std::span<const std::uint8_t> image;
};

void driveOnce(std::span<const std::uint8_t> image, const SC::ChunkedReadOptions& opts)
{
    ImageConnection conn(image);
    try {
        const auto file = SC::readChunkedFile(conn, opts);
        (void)file.size();
    } catch (const std::exception&) {
        // documented rejection path -- keep fuzzing
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::span<const std::uint8_t> image(data, size);

    // Shape 1: six-byte header, u16 length at offset 4, 0xFF-at-4 means empty.
    {
        SC::ChunkedReadOptions opts;
        opts.headerSpec.headerSize = 6;
        opts.headerSpec.lengthOffset = 4;
        opts.headerSpec.lengthBytes = 2;
        opts.headerSpec.hasEmptyMarker = true;
        opts.headerSpec.emptyMarkerOffset = 4;
        opts.headerSpec.emptyMarkerValue = 0xFF;
        opts.includeHeaderInResult = true;
        opts.errorPrefix = "fuzz/spec6";
        driveOnce(image, opts);
    }

    // Shape 2: four-byte header, u16 length at offset 2, body only.
    {
        SC::ChunkedReadOptions opts;
        opts.headerSpec.headerSize = 4;
        opts.headerSpec.lengthOffset = 2;
        opts.headerSpec.lengthBytes = 2;
        opts.errorPrefix = "fuzz/spec4";
        driveOnce(image, opts);
    }

    // Shape 3: a caller-supplied header parser. It takes the card at its word,
    // which is the whole point: nothing in the header spec constrains what a
    // custom parser returns, so the only thing standing between this input and
    // a multi-gigabyte reservation is the read cap.
    {
        SC::ChunkedReadOptions opts;
        opts.headerSpec.headerSize = 8;
        opts.errorPrefix = "fuzz/custom";
        opts.parseHeader = [](std::span<const std::uint8_t> hdr) -> std::optional<SC::HeaderParseResult> {
            if (hdr.size() < 8) {
                return std::nullopt;
            }
            std::size_t declared = 0;
            for (int i = 0; i < 4; ++i) {
                declared |= static_cast<std::size_t>(hdr[i]) << (8 * i);
            }
            return SC::HeaderParseResult{8, declared};
        };
        driveOnce(image, opts);
    }

    return 0;
}

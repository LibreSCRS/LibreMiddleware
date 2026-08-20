// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "rs_container.h"
#include "synthetic_annex.h"

using namespace LibreSCRS::RsEId::Core;
namespace Fx = LibreSCRS::RsEId::Core::TestData;

// The outer tag repeats the file id, so a container read from the wrong FID is
// detectable without consulting the signature.
TEST(RsContainer, OuterTagEqualsFileId)
{
    EXPECT_EQ(outerTag(Fx::makeContainer(0x0F02, {{1548, "ID000000000"}}, 157)), 0x0F02u);
    EXPECT_EQ(outerTag(Fx::makeContainer(0x0FA1, {{554, "0123456789ABCDEF"}}, 26)), 0x0FA1u);
}

// Padding is not signed; the hashed unit is exactly tag+len+value.
TEST(RsContainer, LeadingTlvStripsPadding)
{
    const auto c = Fx::makeContainer(0x0F02, {{1548, "ID000000000"}}, 157);
    const auto tlv = leadingTlv(c);
    ASSERT_TRUE(tlv.has_value());
    EXPECT_EQ(tlv->size(), 4u + 4u + 11u);
    EXPECT_LT(tlv->size(), c.size());
}

TEST(RsContainer, LeadingTlvRejectsDeclaredLengthOverrun)
{
    const std::vector<std::uint8_t> bad{0x02, 0x0F, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};
    EXPECT_FALSE(leadingTlv(bad).has_value());
}

TEST(RsContainer, LeadingTlvRejectsRunt)
{
    const std::vector<std::uint8_t> runt{0x02, 0x0F, 0x01};
    EXPECT_FALSE(leadingTlv(runt).has_value());
    EXPECT_FALSE(outerTag(runt).has_value());
}

TEST(RsContainer, ManifestListsFileIdsInOrder)
{
    const auto m = Fx::makeManifest({0x0F02, 0x0F03, 0x0F04, 0x0FA1, 0x0F1C, 0x0F1D}, 150);
    EXPECT_EQ(parseManifest(m), (std::vector<std::uint16_t>{0x0F02, 0x0F03, 0x0F04, 0x0FA1, 0x0F1C, 0x0F1D}));
}

TEST(RsContainer, ManifestOfNonManifestFileIsEmpty)
{
    const auto notAManifest = Fx::makeContainer(0x0F02, {{1548, "ID000000000"}}, 157);
    EXPECT_TRUE(parseManifest(notAManifest).empty());
}

// Coverage is derived from the manifest, not hardcoded: the fixed object covers
// the manifest first, then every listed file that is neither the variable file
// nor one of the two signed objects.
TEST(RsContainer, CoverageDerivedFromManifest)
{
    const auto m = Fx::makeManifest({0x0F02, 0x0F03, 0x0F04, 0x0FA1, 0x0F1C, 0x0F1D}, 150);
    const auto cov = annexCoverage(parseManifest(m));
    EXPECT_EQ(cov.fixed, (std::vector<std::uint16_t>{0x0F1B, 0x0F02, 0x0F03, 0x0FA1}));
    EXPECT_EQ(cov.variable, (std::vector<std::uint16_t>{0x0F04}));
}

// A card that ships no variable file must yield no variable coverage rather than
// a phantom entry -- the annex contract is "absent means zero groups".
TEST(RsContainer, CoverageWithoutVariableFileIsEmpty)
{
    const auto m = Fx::makeManifest({0x0F02, 0x0F1C}, 60);
    const auto cov = annexCoverage(parseManifest(m));
    EXPECT_EQ(cov.fixed, (std::vector<std::uint16_t>{0x0F1B, 0x0F02}));
    EXPECT_TRUE(cov.variable.empty());
}

// A signed object never covers itself, whichever order the manifest lists them in.
TEST(RsContainer, CoverageNeverIncludesTheSignedObjects)
{
    const auto m = Fx::makeManifest({0x0F1C, 0x0F02, 0x0F1D, 0x0F03}, 60);
    const auto cov = annexCoverage(parseManifest(m));
    EXPECT_EQ(cov.fixed, (std::vector<std::uint16_t>{0x0F1B, 0x0F02, 0x0F03}));
    EXPECT_TRUE(cov.variable.empty());
}

// An unreadable or empty manifest still names the manifest itself, because that
// is the one file the fixed object is known to cover. Callers treat an otherwise
// empty coverage as "no annex" rather than trying to verify a lone container.
TEST(RsContainer, CoverageOfEmptyManifestNamesOnlyTheManifest)
{
    const auto cov = annexCoverage({});
    EXPECT_EQ(cov.fixed, (std::vector<std::uint16_t>{0x0F1B}));
    EXPECT_TRUE(cov.variable.empty());
}

// A signed object is wrapped twice: the container whose tag repeats the file id,
// and an inner TLV that sits between it and the CMS itself.
TEST(RsContainer, InnerTlvPayloadStripsTheSecondHeader)
{
    const std::vector<std::uint8_t> cms{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00};
    std::vector<std::uint8_t> inner{0x10, 0x08};
    Fx::appendLe16(inner, static_cast<std::uint16_t>(cms.size()));
    inner.insert(inner.end(), cms.begin(), cms.end());

    const auto out = innerTlvPayload(inner);
    EXPECT_EQ(std::vector<std::uint8_t>(out.begin(), out.end()), cms);
}

// Content that already begins with an ASN.1 SEQUENCE has nothing wrapping it.
TEST(RsContainer, InnerTlvPayloadLeavesBareDerAlone)
{
    const std::vector<std::uint8_t> der{0x30, 0x80, 0x00, 0x00, 0x00};
    EXPECT_EQ(innerTlvPayload(der).size(), der.size());
}

TEST(RsContainer, InnerTlvPayloadLeavesRuntAlone)
{
    const std::vector<std::uint8_t> runt{0x10, 0x08, 0x01};
    EXPECT_EQ(innerTlvPayload(runt).size(), runt.size());
}

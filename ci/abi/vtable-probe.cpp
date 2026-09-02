#include <LibreSCRS/Plugin/CardPlugin.h>
namespace {
struct VtProbe : LibreSCRS::Plugin::CardPlugin {
    LibreSCRS::Plugin::CardCapabilities capabilities() const override { return {}; }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override { return {}; }
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    { return LibreSCRS::Plugin::ReadResult::cancelled(); }
};
}
LibreSCRS::Plugin::CardPlugin* makeProbe();
LibreSCRS::Plugin::CardPlugin* makeProbe() { return new VtProbe(); }

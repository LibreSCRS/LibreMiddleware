# Link-time optimisation off, explicitly. Fedora's default %%optflags carry
# -flto=auto -ffat-lto-objects, and that conflicts with the bundled static
# OpenSC exactly as this project's own Arch recipe has recorded for a while
# (options=('!lto')). Debian does not enable LTO by default, which is why this
# line has no counterpart there and why one recipe mechanically translated into
# the other would have been wrong.
%global _lto_cflags %{nil}

Name:           librescrs-middleware
Version:        5.0.0
Release:        1%{?dist}
Summary:        Smart-card libraries, card plugins and PKCS#11 provider for LibreSCRS

License:        LGPL-2.1-or-later AND Apache-2.0 AND MIT AND OFL-1.1
URL:            https://github.com/LibreSCRS/LibreMiddleware
Source0:        %{name}-%{version}.tar.gz

# The bundled OpenSSL archives carry x86_64 objects only, so no other
# architecture could ever have linked.
ExclusiveArch:  x86_64

BuildRequires:  cmake >= 3.24
BuildRequires:  ninja-build
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  pkgconf-pkg-config
# cmake/GitVersion.cmake does find_package(Git REQUIRED) before project(), so
# configuration does not start without the binary. The tarball has no .git, so
# `git describe` fails and the VERSION file answers instead -- which is the
# intended path, but only reachable once git is installed.
BuildRequires:  git
BuildRequires:  pcsc-lite-devel
BuildRequires:  libxml2-devel
BuildRequires:  zlib-devel
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  python3
# manifest2header.py validates the plugin manifest against its schema and hard
# fails without this, stopping the build at the first generated header.
BuildRequires:  python3-jsonschema

%description
LibreSCRS reads Serbian government smart cards (identity, vehicle and health)
as well as ICAO 9303 travel documents, NIST PIV and PKCS#15 cards, talking to
the reader over PC/SC directly.

This package holds the shared libraries and the PKCS#11 provider module. The
module is installed but not registered with p11-kit; registration is a separate
decision and a separate package.

%package -n librescrs-card-plugins
Summary:        Card plugins for the LibreSCRS smart-card libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description -n librescrs-card-plugins
One plugin per card family, loaded at run time, with the manifest that
describes the fields each one exposes. Without this package the libraries load
and enumerate readers but recognize no card.

%package -n librescrs-pkcs11-direct
Summary:        Register the LibreSCRS PKCS#11 module directly with p11-kit
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Conflicts:      librescrs-agent

%description -n librescrs-pkcs11-direct
Installs the p11-kit declaration that makes PKCS#11-aware applications discover
the LibreSCRS provider in their own process.

This is the alternative to the agent, not a companion to it. The agent
registers a proxy that collects the PIN in its own prompter, behind an
authorization prompt; the direct module takes the PIN inside whichever
application loaded it. Registering both would leave one card with two security
models and let whichever dialog the user typed into decide which one they got,
so the two packages conflict. The package manager switches from one to the
other only when it is told to remove the conflicting package; the download
page names the command for each distribution.

%package        devel
Summary:        Development files for the LibreSCRS smart-card libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}
# The installed CMake config calls find_dependency for PCSC and for OpenSSL
# before it defines a target, so a consumer without these headers fails at
# configuration.
Requires:       pcsc-lite-devel
Requires:       openssl-devel

%description    devel
Headers, linker symbolic links and the CMake package configuration for building
against LibreSCRS.

%prep
%autosetup -n %{name}-%{version}

%build
%cmake -GNinja \
    -DBUILD_TESTING=OFF \
    -DINSTALL_GTEST=OFF \
    -DLIBRESCRS_BUILD_EXAMPLES=OFF \
    -DLIBREMIDDLEWARE_INSTALL_P11KIT_MODULE=ON
%cmake_build

# The link step names thirdparty/curl-install/lib/libcurl.a unconditionally,
# and curl's own GNUInstallDirs would otherwise put it in lib64 here. Assert
# the path by name: without this the only evidence for that fix is that the
# link does not fail, and a regression would be silent on Debian.
test -f %{_vpath_builddir}/thirdparty/curl-install/lib/libcurl.a

%install
%cmake_install

# No %%check. The build host has no reader and no session bus; a package build
# is the wrong place to discover a test failure, and the suites are gated in
# CI.

%files
%license LICENSE
%doc README.md
%{_libdir}/libLibreSCRS_*.so.*
# All three paths -- .so.5.0.0, .so.5 and the bare .so -- belong to the runtime
# package. The p11-kit declaration in librescrs-pkcs11-direct names the bare
# name, and that package is noarch and carries nothing but the declaration, so
# a machine with no -devel installed still has to resolve it.
%{_libdir}/pkcs11/librescrs-pkcs11.so*
%dir %{_datadir}/librescrs
%{_datadir}/librescrs/certificates/

%files -n librescrs-card-plugins
%{_libdir}/librescrs/
%{_datadir}/librescrs/plugins/

%files -n librescrs-pkcs11-direct
%{_datadir}/p11-kit/modules/librescrs.module

%files devel
%{_includedir}/LibreSCRS/
%{_libdir}/libLibreSCRS_*.so
%{_libdir}/cmake/LibreMiddleware/

%changelog
* Fri Sep 04 2026 LibreSCRS <librescrs@proton.me> - 5.0.0-1
- Initial RPM packaging of the LibreSCRS middleware.

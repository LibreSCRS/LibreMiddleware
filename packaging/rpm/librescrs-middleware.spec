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
Summary:        Smart-card runtime libraries for LibreSCRS

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

This package holds the shared libraries. It installs no PKCS#11 module:
applications reach a card through the card agent's provider, which the agent's
own package registers.

%package -n librescrs-card-plugins
Summary:        Card plugins for the LibreSCRS smart-card libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description -n librescrs-card-plugins
One plugin per card family, loaded at run time, with the manifest that
describes the fields each one exposes. Without this package the libraries load
and enumerate readers but recognize no card.

%package        devel
Summary:        Development files for the LibreSCRS smart-card libraries
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
Headers, linker symbolic links and the CMake package configuration for building
against LibreSCRS.

%prep
%autosetup -n %{name}-%{version}

%build
%cmake -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_TESTING=OFF \
    -DLIBRESCRS_BUILD_EXAMPLES=OFF
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
%dir %{_datadir}/librescrs
%{_datadir}/librescrs/certificates/

%files -n librescrs-card-plugins
%{_libdir}/librescrs/
%{_datadir}/librescrs/plugins/

%files devel
%{_includedir}/LibreSCRS/
%{_libdir}/libLibreSCRS_*.so
%{_libdir}/libLibreSCRSTesting_SmartCard.a
%{_libdir}/cmake/LibreMiddleware/

%changelog
* Fri Sep 04 2026 LibreSCRS <librescrs@proton.me> - 5.0.0-1
- Initial RPM packaging of the LibreSCRS middleware.

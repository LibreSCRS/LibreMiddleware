# LibreSCRS OpenSC Card Driver

An OpenSC external card driver for Serbian smart cards with the CardEdge PKI
applet. Once installed, any PKCS#11-aware application (Firefox, Chrome, SSH,
S/MIME clients) can use these cards transparently via OpenSC's PKCS#11 bridge.

**Supported cards**
- Serbian eID Gemalto (2014+) — matched by ATR `3B:FF:94`
- Serbian eID IF2020 Foreigner — matched by AID
- PKS Chamber of Commerce card — matched by AID

**Not supported**: Apollo 2008 eID (no CardEdge applet).

---

## Build

### Linux

```bash
# Install OpenSC development headers
sudo apt install libopensc-dev          # Debian / Ubuntu
sudo dnf install opensc-devel           # Fedora / RHEL

cmake -S /path/to/LibreMiddleware -B build \
    -DBUILD_OPENSC_DRIVER=ON
cmake --build build --target librescrs-opensc
sudo cp build/lib/opensc-driver/librescrs-opensc.so /usr/local/lib/
```

### macOS

Homebrew installs the OpenSC library but not the development headers.
Clone the OpenSC source at the tag matching your installed version:

```bash
brew install opensc
opensc-tool --version          # note the version, e.g. 0.26.1
git clone --branch 0.26.1 --depth 1 https://github.com/OpenSC/OpenSC /tmp/opensc-src

cmake -S /path/to/LibreMiddleware -B build \
    -DBUILD_OPENSC_DRIVER=ON \
    -DOPENSC_INCLUDE_DIR=/tmp/opensc-src/src
cmake --build build --target librescrs-opensc
sudo cp build/lib/opensc-driver/librescrs-opensc.dylib /usr/local/lib/
```

---

## Configuration

Add the contents of `conf/librescrs.conf` to your `opensc.conf`. Two entries
are required pointing to the **same** shared library file: one to register the
card driver and one to register the PKCS#15 emulator.

| Platform | opensc.conf locations |
|----------|-----------------------|
| Linux    | `/etc/opensc/opensc.conf` · `/etc/opensc.conf` · `~/.config/opensc/opensc.conf` |
| macOS    | `/Library/Application Support/OpenSC/opensc.conf` · `~/Library/Application Support/OpenSC/opensc.conf` · `/opt/homebrew/etc/opensc.conf` |

Minimal configuration (adjust `module` path as needed):

```
app default {
    card_drivers = librescrs, internal;

    card_driver librescrs {
        module = /usr/local/lib/librescrs-opensc.so;   # Linux
        # module = /usr/local/lib/librescrs-opensc.dylib;  # macOS
    }

    framework pkcs15 {
        emulate librescrs {
            module = /usr/local/lib/librescrs-opensc.so;   # Linux
            # module = /usr/local/lib/librescrs-opensc.dylib;  # macOS
        }
    }
}
```

---

## Testing

Insert an eID / PKS card and verify the driver loads correctly.

### 1. Card detection

```bash
opensc-tool --list-readers
# Gemalto USB SmartCard Reader  Slot 0  ATR: 3B FF ...
```

### 2. PKCS#15 objects

```bash
# List certificates
pkcs15-tool --list-certificates

# List private keys
pkcs15-tool --list-keys

# List PIN status (shows tries remaining)
pkcs15-tool --list-pins
```

### 3. Sign and verify

`pkcs15-crypt --sha-256` expects a **pre-computed binary hash** as input
(32 bytes for SHA-256), not the raw message.

```bash
# Compute the hash
openssl dgst -sha256 -binary /path/to/message.txt > /tmp/hash.bin

# Sign with the Digital Signature key (ID 02)
pkcs15-crypt --sign --pkcs1 --sha-256 --key 02 \
    --input /tmp/hash.bin --output /tmp/sig.bin
# Enter PIN when prompted

# Verify with OpenSSL
pkcs15-tool --read-certificate 02 --output /tmp/cert.der
openssl x509 -inform DER -in /tmp/cert.der -pubkey -noout > /tmp/pubkey.pem
openssl dgst -sha256 -verify /tmp/pubkey.pem \
    -signature /tmp/sig.bin /path/to/message.txt
# Verified OK
```

### 4. PKCS#11 (Firefox / Chrome / SSH)

Load `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` (Linux) or
`/opt/homebrew/lib/opensc-pkcs11.so` (macOS) in your application's
security module settings.

```bash
# List PKCS#11 slots
pkcs11-tool --module /opt/homebrew/lib/opensc-pkcs11.so --list-slots

# List certificates via PKCS#11
pkcs11-tool --module /opt/homebrew/lib/opensc-pkcs11.so --list-objects --type cert
```

---

## Debugging

Enable OpenSC debug logging by adding to `opensc.conf`:

```
app default {
    debug = 3;
    debug_file = /tmp/opensc-debug.txt;
    ...
}
```

Then inspect `/tmp/opensc-debug.txt` after running any `pkcs15-tool` or
`pkcs11-tool` command.

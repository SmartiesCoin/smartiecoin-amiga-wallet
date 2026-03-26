# Smartiecoin Amiga Wallet

The world's first cryptocurrency SPV wallet for AmigaOS.

A fully autonomous SPV (Simplified Payment Verification) wallet written in **pure C**, designed to compile with the **VBCC** compiler for AmigaOS 3.x on Motorola 68k processors.

## Features

- **Pure C** - No C++ dependencies, no external libraries
- **SPV Node** - Connects directly to the Smartiecoin P2P network
- **Block header verification** - Downloads and validates the full header chain (~3.2 MB)
- **Bloom filters (BIP37)** - Efficiently filters transactions relevant to your wallet
- **Merkle proof verification** - Cryptographically verifies your transactions are in blocks
- **P2PKH transactions** - Send and receive Smartiecoin (addresses starting with `S`)
- **Encrypted wallet** - Private keys stored encrypted with passphrase
- **Native Amiga GUI** - Uses Intuition/GadTools for a native Workbench experience
- **Cross-platform** - Also builds on Linux/macOS/Windows for testing

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 68020 | 68060 |
| RAM | 4 MB | 128 MB |
| Storage | 8 MB free | 16 MB free |
| Network | SLIP/PPP or Ethernet | Ethernet (PCMCIA/Zorro) |
| OS | AmigaOS 3.0 | AmigaOS 3.1+ |
| TCP/IP | bsdsocket.library v4+ | AmiTCP / Roadshow |

## Building

### For AmigaOS (VBCC)

Follow the [VBCC setup guide](docs/vbcc-setup.md) to install the compiler, then:

```
vc -c99 -O2 -DAMIGA -I src -o SmartiecoinWallet src/*.c src/crypto/*.c src/net/*.c src/wallet/*.c src/spv/*.c src/gui/*.c src/platform/*.c -lauto -lm
```

Or use the Makefile:

```
make amiga
```

### For PC Testing (GCC/Clang)

```
make pc
```

## Architecture

```
src/
├── crypto/          Cryptographic primitives
│   ├── sha256       SHA-256 (single and double)
│   ├── ripemd160    RIPEMD-160 and HASH160
│   ├── base58       Base58Check encoding/decoding
│   └── secp256k1    Elliptic curve + ECDSA signing
├── net/             Network layer
│   ├── serialize    Binary wire format serialization
│   └── p2p          P2P protocol (version, headers, tx, inv, merkleblock)
├── wallet/          Wallet functionality
│   ├── keys         Key generation, import/export (WIF), encrypted storage
│   ├── address      Address creation and validation
│   └── tx           Transaction building, signing, UTXO management
├── spv/             SPV verification
│   ├── headers      Block header chain storage and sync
│   ├── bloom        Bloom filters (BIP37) for tx filtering
│   └── merkle       Merkle proof verification
├── gui/             User interface
│   └── intuition    Amiga Intuition/GadTools GUI (+ console fallback)
├── platform/        Platform abstraction
│   └── amiga_net    Network (bsdsocket.library / BSD sockets)
├── chainparams.h    Smartiecoin network parameters
├── types.h          Portable type definitions
└── main.c           Application entry point and event loop
```

## How It Works

1. **Startup**: Loads or creates an encrypted wallet file
2. **Connect**: Connects to Smartiecoin P2P network via seed nodes
3. **Sync headers**: Downloads all block headers (~80 bytes each, ~3.2 MB total)
4. **Bloom filter**: Sends a bloom filter containing your addresses to peers
5. **Monitor**: Receives `merkleblock` + `tx` messages for matching transactions
6. **Verify**: Validates Merkle proofs to confirm transactions are in blocks
7. **Send**: Creates, signs, and broadcasts P2PKH transactions

## Network Parameters

| Parameter | Value |
|-----------|-------|
| Address prefix | `63` (starts with `S`) |
| WIF prefix | `128` |
| P2P port | `8383` |
| Protocol version | `70230` |
| Magic bytes | `E4 BA B3 C7` |

## Security Notes

- Private keys are encrypted at rest using SHA-256 derived keystream
- secp256k1 signing uses RFC 6979 deterministic k for safety
- Key material is securely wiped from memory on shutdown
- The wallet connects to the P2P network directly - no trusted third party

## License

MIT License - See [LICENSE](LICENSE) for details.

#
# Smartiecoin Amiga Wallet - Makefile
#
# Usage:
#   For AmigaOS (VBCC):  make amiga
#   For PC testing:      make pc
#   Clean:               make clean
#

# ---- Source files ----
CRYPTO_SRC = src/crypto/sha256.c \
             src/crypto/ripemd160.c \
             src/crypto/base58.c \
             src/crypto/secp256k1.c

NET_SRC    = src/net/serialize.c \
             src/net/p2p.c

WALLET_SRC = src/wallet/address.c \
             src/wallet/keys.c \
             src/wallet/tx.c

SPV_SRC    = src/spv/headers.c \
             src/spv/bloom.c \
             src/spv/merkle.c

GUI_SRC    = src/gui/intuition_gui.c

PLATFORM_SRC = src/platform/amiga_net.c

MAIN_SRC   = src/main.c

ALL_SRC    = $(CRYPTO_SRC) $(NET_SRC) $(WALLET_SRC) $(SPV_SRC) \
             $(GUI_SRC) $(PLATFORM_SRC) $(MAIN_SRC)

# ---- AmigaOS / VBCC build ----
VC       = vc
VFLAGS   = -c99 -O2 -DAMIGA -I src
VLIBS    = -lauto -lm

amiga: $(ALL_SRC)
	$(VC) $(VFLAGS) -o SmartiecoinWallet $(ALL_SRC) $(VLIBS)

# ---- PC testing build (GCC/Clang) ----
CC       = gcc
CFLAGS   = -std=c99 -Wall -Wextra -O2 -g -I src
LDFLAGS  =

# Platform-specific libs
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME_S),Linux)
    LDFLAGS += -lm
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -lm
endif
ifeq ($(UNAME_S),Windows)
    LDFLAGS += -lws2_32
endif

OBJS = $(ALL_SRC:.c=.o)

pc: $(OBJS)
	$(CC) $(CFLAGS) -o smartiecoin-wallet $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ---- Clean ----
clean:
	rm -f SmartiecoinWallet smartiecoin-wallet
	rm -f $(OBJS)
	rm -f src/crypto/*.o src/net/*.o src/wallet/*.o
	rm -f src/spv/*.o src/gui/*.o src/platform/*.o src/*.o

.PHONY: amiga pc clean

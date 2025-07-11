# =============================
# Nama dan folder utama
# =============================
TARGET = orisium
SRC_DIR = src
OBJ_DIR = obj

# =============================
# Compiler dan flags
# =============================

CC = gcc
GCC_INCLUDE_DIRS := $(shell echo '' | gcc -E -x c - -v 2>&1 | awk '/^ \/.*\/include/ { print "-I" $$1 }')
INCLUDE_DIR = $(GCC_INCLUDE_DIRS) -I./$(SRC_DIR)/include -I./PQClean -I./PQClean/common -I./lmdb/libraries/liblmdb
COMMON_CFLAGS = -Wall -Wextra -Wno-unused-parameter -Werror=implicit-function-declaration -pthread -mrdseed -ljson-c -lm $(INCLUDE_DIR)
BUILD_MODE ?= DEVELOPMENT
DEBUG_MODE ?= DEVELOPMENT
LOG_TO ?= SCREEN
ifeq ($(BUILD_MODE), PRODUCTION)
    FINAL_CFLAGS = $(COMMON_CFLAGS) -O3 -DNDEBUG -DPRODUCTION
else
	ifeq ($(LOG_TO), FILE)
		FINAL_CFLAGS = $(COMMON_CFLAGS) -fsanitize=address -fsanitize=leak -g -O3 -Werror -DDEVELOPMENT -DTOFILE
	else
		FINAL_CFLAGS = $(COMMON_CFLAGS) -fsanitize=address -fsanitize=leak -g -O3 -Werror -DNDEBUG -DDEVELOPMENT -DTOSCREEN
	endif
endif
LDFLAGS =

# =============================
# Deteksi Distribusi Linux dan Package Manager
# =============================
DISTRO_ID := $(shell . /etc/os-release 2>/dev/null && echo $$ID || echo unknown)

PKG_MANAGER := $(shell \
	if [ "$(DISTRO_ID)" = "rocky" ] || [ "$(DISTRO_ID)" = "fedora" ]; then echo "dnf"; \
	elif [ "$(DISTRO_ID)" = "centos" ]; then \
		if command -v dnf >/dev/null 2>&1; then echo "dnf"; else echo "yum"; fi; \
	elif [ "$(DISTRO_ID)" = "rhel" ]; then \
		if command -v dnf >/dev/null 2>&1; then echo "dnf"; else echo "yum"; fi; \
	elif [ "$(DISTRO_ID)" = "debian" ] || [ "$(DISTRO_ID)" = "ubuntu" ]; then echo "apt"; \
	elif [ "$(DISTRO_ID)" = "arch" ]; then echo "pacman"; \
	elif [ "$(DISTRO_ID)" = "opensuse" ]; then echo "zypper"; \
	else echo "unsupported"; fi)

USE_SUDO := $(shell command -v sudo >/dev/null 2>&1 && echo sudo || echo "")

# =============================
# Source & Object Files
# =============================
SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# =============================
# PQClean Libraries
# =============================
PQCLEAN_COMMON_DIR = PQClean/common
PQCLEAN_COMMON_SRCS = $(wildcard $(PQCLEAN_COMMON_DIR)/*.c)
PQCLEAN_COMMON_OBJS = $(addprefix $(OBJ_DIR)/, $(notdir $(PQCLEAN_COMMON_SRCS:.c=.o)))

PQCLEAN_SIGN_MLDSA87_DIR = PQClean/crypto_sign/ml-dsa-87/clean
PQCLEAN_SIGN_MLDSA87_LIB_NAME = libml-dsa-87_clean.a
PQCLEAN_SIGN_MLDSA87_LIB_PATH = $(PQCLEAN_SIGN_MLDSA87_DIR)/$(PQCLEAN_SIGN_MLDSA87_LIB_NAME)

PQCLEAN_SIGN_FALCONPADDED512_DIR = PQClean/crypto_sign/falcon-padded-512/clean
PQCLEAN_SIGN_FALCONPADDED512_LIB_NAME = libfalcon-padded-512_clean.a
PQCLEAN_SIGN_FALCONPADDED512_LIB_PATH = $(PQCLEAN_SIGN_FALCONPADDED512_DIR)/$(PQCLEAN_SIGN_FALCONPADDED512_LIB_NAME)

PQCLEAN_KEM_DIR = PQClean/crypto_kem/ml-kem-1024/clean
PQCLEAN_KEM_LIB_NAME = libml-kem-1024_clean.a
PQCLEAN_KEM_LIB_PATH = $(PQCLEAN_KEM_DIR)/$(PQCLEAN_KEM_LIB_NAME)

# =============================
# LMDB Configuration
# =============================
LMDB_DIR = lmdb/libraries/liblmdb
LMDB_LIB_NAME = liblmdb.a
LMDB_LIB_PATH = $(LMDB_DIR)/$(LMDB_LIB_NAME)

# =============================
# IWYU Configuration
# =============================
IWYU_DIR := iwyu
IWYU_BUILD := build
IWYU_BUILD_PATH := $(IWYU_DIR)/$(IWYU_BUILD)
IWYU_BIN_PATH := $(IWYU_BUILD_PATH)/bin/include-what-you-use

EXCLUDED_DIRS := PQClean iwyu lmdb
EXCLUDE_PATHS := $(foreach dir,$(EXCLUDED_DIRS),-path ./$(dir) -prune -o)
CFILES := $(shell find . $(EXCLUDE_PATHS) -name '*.c' -print)

# =============================
# Build Targets
# =============================
.PHONY: all dev prod clean run debug check_iwyu

# Target default
all: prod
	
define install_pkg
	@echo "🔧 Menginstall $(1)..."
	@if [ "$(PKG_MANAGER)" = "unsupported" ]; then \
		echo "❌ Distribusi tidak didukung. Install $(1) secara manual."; \
	elif [ "$(PKG_MANAGER)" = "apt" ]; then \
		$(USE_SUDO) apt update && $(USE_SUDO) apt install -y $(1) || true; \
	elif [ "$(PKG_MANAGER)" = "dnf" ] || [ "$(PKG_MANAGER)" = "yum" ]; then \
		$(USE_SUDO) $(PKG_MANAGER) install -y $(1) || true; \
	elif [ "$(PKG_MANAGER)" = "pacman" ]; then \
		$(USE_SUDO) pacman -S --noconfirm $(1) || true; \
	elif [ "$(PKG_MANAGER)" = "zypper" ]; then \
		$(USE_SUDO) zypper install -y $(1) || true; \
	else \
		echo "⚠️ Tidak bisa menginstall $(1)."; \
	fi
endef

dev-libraries:
	@echo "📥 Menginstall library development Orisium untuk $(DISTRO_ID) menggunakan $(PKG_MANAGER)..."
	$(call install_pkg,json-c)
	$(call install_pkg,json-c-devel)
	$(call install_pkg,libasan)
	$(call install_pkg,python3)

prod-libraries:
	@echo "📥 Menginstall library production Orisium untuk $(DISTRO_ID) menggunakan $(PKG_MANAGER)..."
	$(call install_pkg,json-c)
	$(call install_pkg,json-c-devel)
	$(call install_pkg,python3)	

dev:
	$(MAKE) dev-libraries check_iwyu $(TARGET)
	@echo "-------------------------------------"
	@echo "orisium dikompilasi dalam mode DEVELOPMENT!"
	@echo "Executable: $(TARGET)"
	@echo "-------------------------------------"

prod:
	$(MAKE) prod-libraries check_iwyu $(TARGET) BUILD_MODE=PRODUCTION
	@echo "-------------------------------------"
	@echo "orisium dikompilasi dalam mode PRODUCTION!"
	@echo "Executable: $(TARGET)"
	@echo "-------------------------------------"
	
$(TARGET): $(OBJS) $(PQCLEAN_COMMON_OBJS) \
		$(PQCLEAN_SIGN_MLDSA87_LIB_PATH) \
		$(PQCLEAN_SIGN_FALCONPADDED512_LIB_PATH) \
		$(PQCLEAN_KEM_LIB_PATH) \
	    $(LMDB_LIB_PATH)
	$(CC) $(FINAL_CFLAGS) $^ -o $@ $(LDFLAGS)

# =============================
# Compile Rules
# =============================
# Rule untuk file .c dari SRC_DIR
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(FINAL_CFLAGS) -c -o $@ $<

# Rule untuk file .c dari PQClean/common
$(OBJ_DIR)/%.o: $(PQCLEAN_COMMON_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(FINAL_CFLAGS) -c $< -o $@

# =============================
# PQClean Build Rules
# =============================
$(PQCLEAN_SIGN_MLDSA87_LIB_PATH):
	@echo "Membangun ML-DSA-87..."
	@echo "📥 Membangun dari sumber..."
	@if [ ! -f "$(PQCLEAN_SIGN_MLDSA87_LIB_PATH)" ]; then \
		$(MAKE) -C $(PQCLEAN_SIGN_MLDSA87_DIR); \
	else \
		echo "✅ Library sudah ada: $@"; \
	fi

$(PQCLEAN_SIGN_FALCONPADDED512_LIB_PATH):
	@echo "Membangun Falcon-Padded-512..."
	@echo "📥 Membangun dari sumber..."
	@if [ ! -f "$(PQCLEAN_SIGN_FALCONPADDED512_LIB_PATH)" ]; then \
		$(MAKE) -C $(PQCLEAN_SIGN_FALCONPADDED512_DIR); \
	else \
		echo "✅ Library sudah ada: $@"; \
	fi

$(PQCLEAN_KEM_LIB_PATH):
	@echo "Membangun ML-KEM-1024..."
	@echo "📥 Membangun dari sumber..."
	@if [ ! -f "$(PQCLEAN_KEM_LIB_PATH)" ]; then \
		$(MAKE) -C $(PQCLEAN_KEM_DIR); \
	else \
		echo "✅ Library sudah ada: $@"; \
	fi
	
# =============================
# Bangun LMDB (jika belum ada)
# =============================
$(LMDB_LIB_PATH):
	@echo "-------------------------------------"
	@echo "Membangun pustaka LMDB..."
	@echo "-------------------------------------"
	@if [ -f "$(LMDB_LIB_PATH)" ]; then \
		echo "LMDB library sudah ada. Melewati build."; \
	else \
		$(MAKE) -C $(LMDB_DIR); \
	fi

# =============================
# IWYU Check
# =============================
check_iwyu: $(IWYU_BIN_PATH)
	@echo "🔍 Menjalankan IWYU untuk *.c (kecuali: $(EXCLUDED_DIRS))..."
	@rm -f iwyu_failed.log iwyu_applied.log
	@for file in $(CFILES); do \
		echo "🧪 $$file"; \
		$(IWYU_BIN_PATH) $(FINAL_CFLAGS) "$$file" > /tmp/iwyu.tmp 2>&1; \
		if grep -q "should" /tmp/iwyu.tmp; then \
			echo "❌ IWYU error in $$file" | tee -a iwyu_failed.log; \
			cat /tmp/iwyu.tmp >> iwyu_failed.log; \
			echo "" >> iwyu_failed.log; \
			python3 $(IWYU_DIR)/fix_includes.py < /tmp/iwyu.tmp >> iwyu_applied.log 2>&1; \
			echo "🔧 FIX applied to $$file" >> iwyu_applied.log; \
		else \
			echo "✅ Tidak ada masalah di $$file."; \
		fi; \
		rm -f /tmp/iwyu.tmp; \
	done; \
	if [ -f iwyu_failed.log ]; then \
		echo "📌 IWYU sudah diperbaiki secara otomatis, log: iwyu_applied.log"; \
	else \
		echo "✅ Semua file bersih dari masalah IWYU."; \
	fi

# =============================
# Bangun IWYU (jika belum ada)
# =============================
$(IWYU_BIN_PATH):
	@echo "🔧 Membangun IWYU..."
	@if [ ! -f "$(IWYU_BIN_PATH)" ]; then \
		echo "📥 Membangun dari sumber..."; \
		echo "📥 Memeriksa dan menginstall dependensi IWYU untuk distro $(DISTRO_ID) menggunakan $(PKG_MANAGER)..."; \
		PKGS="cmake clang llvm clang-devel llvm-devel"; \
		for pkg in $$PKGS; do \
			if [ "$(PKG_MANAGER)" = "unsupported" ]; then \
				echo "❌ Tidak bisa install $$pkg. Distribusi tidak didukung."; \
				exit 1; \
			elif [ "$(PKG_MANAGER)" = "apt" ]; then \
				$(USE_SUDO) apt update && $(USE_SUDO) apt install -y cmake clang llvm || true; \
				break; \
			elif [ "$(PKG_MANAGER)" = "dnf" ] || [ "$(PKG_MANAGER)" = "yum" ]; then \
				$(USE_SUDO) $(PKG_MANAGER) install -y cmake clang llvm clang-devel llvm-devel || true; \
				break; \
			elif [ "$(PKG_MANAGER)" = "pacman" ]; then \
				$(USE_SUDO) pacman -Syu --noconfirm cmake clang llvm || true; \
				break; \
			elif [ "$(PKG_MANAGER)" = "zypper" ]; then \
				$(USE_SUDO) zypper install -y cmake clang llvm || true; \
				break; \
			fi; \
		done; \
		CLANG_MAJOR_VER=$$(clang --version | head -n1 | sed 's/[^0-9]*\([0-9][0-9]*\)\..*/\1/'); \
		echo "📌 Deteksi Clang versi $$CLANG_MAJOR_VER"; \
		cd $(IWYU_DIR) && \
		if [ "$$CLANG_MAJOR_VER" -ge 10 ] && [ "$$CLANG_MAJOR_VER" -le 20 ]; then \
			git checkout clang_$$CLANG_MAJOR_VER || echo "⚠️ Branch clang_$$CLANG_MAJOR_VER tidak ditemukan"; \
		else \
			echo "⚠️ Versi clang tidak dikenali. Lewati checkout branch."; \
		fi && \
		mkdir -p $(IWYU_BUILD) && \
		cd $(IWYU_BUILD) && \
		cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -DLLVM_DIR=/usr/lib64/cmake/llvm && \
		$(MAKE) -j4; \
	else \
		echo "✅ IWYU sudah tersedia."; \
	fi

# =============================
# Targets tambahan
# =============================
clean:
	@echo "Membersihkan file objek dan executable..."
	rm -rf $(OBJ_DIR) $(TARGET) iwyu_failed.log

run: $(TARGET)
	@echo "Menjalankan Orisium..."
	./$(TARGET)
	
debug: dev
	@echo "🚀 Menjalankan Orisium dengan AddressSanitizer (ASAN)..."
	ASAN_OPTIONS=detect_leaks=1 ./$(TARGET)

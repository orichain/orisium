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
INCLUDE_DIR = $(GCC_INCLUDE_DIRS) -I./$(SRC_DIR)/include -I./PQClean -I./PQClean/common
COMMON_CFLAGS = -Wall -Wextra -Wno-unused-parameter -Werror=implicit-function-declaration -pthread -mrdseed -ljson-c $(INCLUDE_DIR)
BUILD_MODE ?= DEVELOPMENT
LOG_TO ?= SCREEN
ifeq ($(BUILD_MODE), PRODUCTION)
	FINAL_CFLAGS = $(COMMON_CFLAGS) -O3 -DNDEBUG -DPRODUCTION
else
	ifeq ($(LOG_TO), FILE)
		FINAL_CFLAGS = $(COMMON_CFLAGS) -fsanitize=address -fsanitize=leak -g -O3 -Werror -DDEVELOPMENT -DTOFILE
	else
		FINAL_CFLAGS = $(COMMON_CFLAGS) -fsanitize=address -fsanitize=leak -g -O3 -Werror -DDEVELOPMENT -DTOSCREEN
	endif
endif
LDFLAGS =

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
# JSON-C Configuration
# =============================
JSON_C_H_PATH := /usr/include/json-c/json.h

# =============================
# IWYU Configuration
# =============================
IWYU_DIR := iwyu
IWYU_BUILD := build
IWYU_BUILD_PATH := $(IWYU_DIR)/$(IWYU_BUILD)
IWYU_BIN_PATH := $(IWYU_BUILD_PATH)/bin/include-what-you-use

EXCLUDED_DIRS := PQClean iwyu
EXCLUDE_PATHS := $(foreach dir,$(EXCLUDED_DIRS),-path ./$(dir) -prune -o)
CFILES := $(shell find . $(EXCLUDE_PATHS) -name '*.c' -print)

# =============================
# Package Manager Detection
# =============================
# Deteksi manajer paket
ifeq ($(shell command -v yum 2>/dev/null),) # Coba yum dulu
	ifeq ($(shell command -v dnf 2>/dev/null),)
		ifeq ($(shell command -v apt-get 2>/dev/null),)
			ifeq ($(shell command -v pacman 2>/dev/null),)
				ifeq ($(shell command -v zypper 2>/dev/null),)
					$(error "Tidak ada manajer paket (yum, dnf, apt, pacman, zypper) yang ditemukan.")
				else
					PACKAGE_MANAGER = zypper
					INSTALL_CMD = sudo zypper install -y
					QUERY_CMD = zypper search --installed
				endif
			else
				PACKAGE_MANAGER = pacman
				INSTALL_CMD = sudo pacman -S --noconfirm
				QUERY_CMD = pacman -Q
			endif
		else
			PACKAGE_MANAGER = apt
			INSTALL_CMD = sudo apt-get install -y
			QUERY_CMD = dpkg -s
		endif
	else
		PACKAGE_MANAGER = dnf
		INSTALL_CMD = sudo dnf install -y
		QUERY_CMD = dnf list installed
	endif
else
	PACKAGE_MANAGER = yum
	INSTALL_CMD = sudo yum install -y
	QUERY_CMD = yum list installed
endif

# Fungsi untuk memeriksa dan menginstal paket
define install_package
	@echo "🔧 Memeriksa dan menginstal $(1) menggunakan $(PACKAGE_MANAGER)..."
	@if [ "$(PACKAGE_MANAGER)" = "dnf" ] || [ "$(PACKAGE_MANAGER)" = "yum" ] || [ "$(PACKAGE_MANAGER)" = "zypper" ]; then \
		$(QUERY_CMD) $(1) >/dev/null 2>&1 || $(INSTALL_CMD) $(1) || true; \
	elif [ "$(PACKAGE_MANAGER)" = "apt" ]; then \
		$(QUERY_CMD) $(1) >/dev/null 2>&1 || $(INSTALL_CMD) $(1) || true; \
	elif [ "$(PACKAGE_MANAGER)" = "pacman" ]; then \
		$(QUERY_CMD) $(1) >/dev/null 2>&1 || $(INSTALL_CMD) $(1) || true; \
	fi
endef

# =============================
# Build Targets
# =============================
.PHONY: all dev prod clean run debug check_iwyu install_dev_libraries install_prod_libraries

# Target default
all: prod

install_dev_libraries:
	@echo "📥 Menginstal library yang dibutuhkan Orisium dengan $(PACKAGE_MANAGER)..."
	$(call install_package,json-c)
	$(call install_package,json-c-devel)
	$(call install_package,libasan)
	$(call install_package,python3)

install_prod_libraries:
	@echo "📥 Menginstal library yang dibutuhkan Orisium dengan $(PACKAGE_MANAGER)..."
	$(call install_package,json-c)
	$(call install_package,json-c-devel)

dev:
	$(MAKE) install_dev_libraries check_iwyu $(TARGET)
	@echo "-------------------------------------"
	@echo "orisium dikompilasi dalam mode DEVELOPMENT!"
	@echo "Executable: $(TARGET)"
	@echo "-------------------------------------"

prod:
	$(MAKE) install_prod_libraries $(TARGET) BUILD_MODE=PRODUCTION
	@echo "-------------------------------------"
	@echo "orisium dikompilasi dalam mode PRODUCTION!"
	@echo "Executable: $(TARGET)"
	@echo "-------------------------------------"

$(TARGET): $(OBJS) $(PQCLEAN_COMMON_OBJS) \
		$(PQCLEAN_SIGN_MLDSA87_LIB_PATH) \
		$(PQCLEAN_SIGN_FALCONPADDED512_LIB_PATH) \
		$(PQCLEAN_KEM_LIB_PATH)
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
	@if [ ! -f "$@" ]; then \
		$(MAKE) -C $(PQCLEAN_SIGN_MLDSA87_DIR); \
	else \
		echo "✅ Library sudah ada: $@"; \
	fi

$(PQCLEAN_SIGN_FALCONPADDED512_LIB_PATH):
	@echo "Membangun Falcon-Padded-512..."
	@echo "📥 Membangun dari sumber..."
	@if [ ! -f "$@" ]; then \
		$(MAKE) -C $(PQCLEAN_SIGN_FALCONPADDED512_DIR); \
	else \
		echo "✅ Library sudah ada: $@"; \
	fi

$(PQCLEAN_KEM_LIB_PATH):
	@echo "Membangun ML-KEM-1024..."
	@echo "📥 Membangun dari sumber..."
	@if [ ! -f "$@" ]; then \
		$(MAKE) -C $(PQCLEAN_KEM_DIR); \
	else \
		echo "✅ Library sudah ada: $@"; \
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
		echo "📥 Menginstal library yang dibutuhkan IWYU dengan $(PACKAGE_MANAGER)..."; \
		$(call install_package,cmake); \
		$(call install_package,clang); \
		if [ "$(PACKAGE_MANAGER)" = "dnf" ] || [ "$(PACKAGE_MANAGER)" = "yum" ] || [ "$(PACKAGE_MANAGER)" = "zypper" ]; then \
			$(call install_package,llvm-devel); \
			$(call install_package,clang-devel); \
		elif [ "$(PACKAGE_MANAGER)" = "apt" ]; then \
			$(call install_package,libllvm-$(shell clang --version | head -n1 | sed 's/[^0-9]*\([0-9][0-9]*\)\..*/\1/')-dev); \
			$(call install_package,libclang-$(shell clang --version | head -n1 | sed 's/[^0-9]*\([0-9][0-9]*\)\..*/\1/')-dev); \
		elif [ "$(PACKAGE_MANAGER)" = "pacman" ]; then \
			$(call install_package,llvm); \
			$(call install_package,clang); \
		fi; \
		CLANG_MAJOR_VER=$$(clang --version | head -n1 | sed 's/[^0-9]*\([0-9][0-9]*\)\..*/\1/'); \
		echo "📌 Deteksi Clang versi $$CLANG_MAJOR_VER"; \
		cd $(IWYU_DIR) && \
		if [ "$$CLANG_MAJOR_VER" = "10" ]; then \
			git checkout clang_10; \
		elif [ "$$CLANG_MAJOR_VER" = "11" ]; then \
			git checkout clang_11; \
		elif [ "$$CLANG_MAJOR_VER" = "12" ]; then \
			git checkout clang_12; \
		elif [ "$$CLANG_MAJOR_VER" = "13" ]; then \
			git checkout clang_13; \
		elif [ "$$CLANG_MAJOR_VER" = "14" ]; then \
			git checkout clang_14; \
		elif [ "$$CLANG_MAJOR_VER" = "15" ]; then \
			git checkout clang_15; \
		elif [ "$$CLANG_MAJOR_VER" = "16" ]; then \
			git checkout clang_16; \
		elif [ "$$CLANG_MAJOR_VER" = "17" ]; then \
			git checkout clang_17; \
		elif [ "$$CLANG_MAJOR_VER" = "18" ]; then \
			git checkout clang_18; \
		elif [ "$$CLANG_MAJOR_VER" = "19" ]; then \
			git checkout clang_19; \
		elif [ "$$CLANG_MAJOR_VER" = "20" ]; then \
			git checkout clang_20; \
		else \
			echo "⚠️ Versi clang tidak dikenali: $$CLANG_MAJOR_VER. Lewati checkout branch."; \
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

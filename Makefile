TARGET = orisium
SRC_DIR = src
OBJ_DIR = obj

CC = ./gcc

JSONC_CFLAGS :=
JSONC_LIBS := -ljson-c

ifneq ($(shell command -v pkg-config 2>/dev/null),)
	JSONC_CFLAGS := $(shell pkg-config --cflags json-c 2>/dev/null)
	JSONC_LIBS := $(shell pkg-config --libs json-c 2>/dev/null)
endif

COMMON_CFLAGS = -Wall -Wextra -Wno-unused-parameter -Werror=implicit-function-declaration -lm $(JSONC_CFLAGS)
LDFLAGS = -pthread $(JSONC_LIBS)

GCC_INCLUDE_DIRS := $(shell echo '' | $(CC) -E -x c - -v 2>&1 | awk '/^ \/.*\/include/ { print "-I" $$1 }')
INCLUDE_DIR = $(GCC_INCLUDE_DIRS) -I./$(SRC_DIR)/include -I./PQClean -I./PQClean/common -I./lmdb/libraries/liblmdb
COMMON_CFLAGS += $(INCLUDE_DIR)

BUILD_MODE ?= DEVELOPMENT
DEBUG_MODE ?= DEVELOPMENT
LOG_TO ?= SCREEN
ifeq ($(BUILD_MODE), PRODUCTION)
	FINAL_CFLAGS = $(COMMON_CFLAGS) -O3 -DNDEBUG -DPRODUCTION
else
	ifeq ($(LOG_TO), FILE)
		FINAL_CFLAGS = $(COMMON_CFLAGS) -g -O3 -Werror -DDEVELOPMENT -DTOFILE
	else
		FINAL_CFLAGS = $(COMMON_CFLAGS) -g -O3 -Werror -DNDEBUG -DDEVELOPMENT -DTOSCREEN
	endif
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),NetBSD)
	DISTRO_ID := netbsd
else ifeq ($(UNAME_S),FreeBSD)
	DISTRO_ID := freebsd
else ifeq ($(UNAME_S),OpenBSD)
	DISTRO_ID := openbsd
else
	DISTRO_ID := $(shell . /etc/os-release 2>/dev/null && echo $$ID || echo unknown)
endif

PKG_MANAGER := $(shell \
	if [ "$(DISTRO_ID)" = "netbsd" ]; then echo "pkgin"; \
	elif [ "$(DISTRO_ID)" = "freebsd" ]; then echo "pkg"; \
	elif [ "$(DISTRO_ID)" = "openbsd" ]; then echo "pkg_add"; \
	elif [ "$(DISTRO_ID)" = "rocky" ]; then echo "dnf"; \
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
HFILES := $(shell find . $(EXCLUDE_PATHS) -name '*.h' -print)

# =============================
# Build Targets
# =============================
.PHONY: all dev prod clean run debug check_iwyu_h check_iwyu_c

all: prod
	
define install_pkg
	@echo ">> Memeriksa: $(1)"
	@if command -v $(1) >/dev/null 2>&1; then \
		echo ">> $(1) sudah tersedia (binary)."; \
	elif [ "$(PKG_MANAGER)" = "unsupported" ]; then \
		echo "!! Distribusi tidak didukung. Install $(1) manual."; \
	elif [ "$(PKG_MANAGER)" = "pkgin" ]; then \
		if pkg_info -e $(1) >/dev/null 2>&1; then \
			echo ">> $(1) sudah terinstal (paket)."; \
		else \
			echo ">> Menginstal $(1) via $(PKG_MANAGER)..."; \
			$(USE_SUDO) $(PKG_MANAGER) -y install $(1) || true; \
		fi; \
	elif [ "$(PKG_MANAGER)" = "pkg" ]; then \
		if pkg info -e $(1) >/dev/null 2>&1; then \
			echo ">> $(1) sudah terinstal (paket)."; \
		else \
			echo ">> Menginstal $(1) via $(PKG_MANAGER)..."; \
			$(USE_SUDO) $(PKG_MANAGER) install -y $(1) || true; \
		fi; \
	elif [ "$(PKG_MANAGER)" = "pkg_add" ]; then \
		if pkg_info -e $(1)-* >/dev/null 2>&1; then \
			echo ">> $(1) sudah terinstal (paket)."; \
		else \
			echo ">> Menginstal $(1) via $(PKG_MANAGER)..."; \
			$(USE_SUDO) $(PKG_MANAGER) $(1) || true; \
		fi; \
	elif [ "$(PKG_MANAGER)" = "dnf" ]; then \
		if dnf list installed $(1) >/dev/null 2>&1; then \
			echo ">> $(1) sudah terinstal (paket)."; \
		else \
			echo ">> Menginstal $(1) via $(PKG_MANAGER)..."; \
			$(USE_SUDO) $(PKG_MANAGER) -y install $(1) || true; \
		fi; \
	else \
		echo "!! Package manager tidak dikenali."; \
	fi
endef

libraries:
	@echo "Menginstall library production Orisium untuk $(DISTRO_ID) menggunakan $(PKG_MANAGER)..."
ifeq ($(DISTRO_ID),netbsd)
	$(call install_pkg,gcc14)
	@if [ ! -e ./gcc ]; then \
		echo ">> Membuat symlink ./gcc..."; \
		$(USE_SUDO) ln -s /usr/pkg/gcc14/bin/gcc ./gcc; \
	else \
		echo ">> ./gcc sudah ada."; \
	fi
	$(call install_pkg,json-c)
	$(call install_pkg,pkg-config)
	$(call install_pkg,python312)
	@if [ ! -e ./python ]; then \
		echo ">> Membuat symlink ./python..."; \
		$(USE_SUDO) ln -s /usr/pkg/bin/python3.12 ./python; \
	else \
		echo ">> ./python sudah ada."; \
	fi
else ifeq ($(DISTRO_ID),freebsd)
	$(call install_pkg,gcc14)
	@if [ ! -e ./gcc ]; then \
		echo ">> Membuat symlink ./gcc..."; \
		$(USE_SUDO) ln -s /usr/local/bin/gcc14 ./gcc; \
	else \
		echo ">> ./gcc sudah ada."; \
	fi
	$(call install_pkg,json-c)
	$(call install_pkg,pkgconf)
	$(call install_pkg,python3)
	@if [ ! -e ./python ]; then \
		echo ">> Membuat symlink ./python..."; \
		$(USE_SUDO) ln -s /usr/local/bin/python3 ./python; \
	else \
		echo ">> ./python sudah ada."; \
	fi
else ifeq ($(DISTRO_ID),openbsd)
	@if [ ! -e ./gcc ]; then \
		echo "======================================"; \
		echo "!!--- PILIH gcc11 / LEBIH TINGGI ---!!"; \
		echo "======================================"; \
	fi
	$(call install_pkg,gcc)
	@if [ ! -e ./gcc ]; then \
		echo ">> Membuat symlink ./gcc..."; \
		$(USE_SUDO) ln -s /usr/local/bin/egcc ./gcc; \
	else \
		echo ">> ./gcc sudah ada."; \
	fi
	$(call install_pkg,json-c)
	@if [ ! -e ./python ]; then \
		echo "========================="; \
		echo "!!--- PILIH python3 ---!!"; \
		echo "========================="; \
	fi
	$(call install_pkg,python)
	@if [ ! -e ./python ]; then \
		echo ">> Membuat symlink ./python..."; \
		$(USE_SUDO) ln -s /usr/local/bin/python3 ./python; \
	else \
		echo ">> ./python sudah ada."; \
	fi
else ifeq ($(DISTRO_ID),rocky)
	@if [ ! -e ./gcc ]; then \
		echo ">> Membuat symlink ./gcc..."; \
		$(USE_SUDO) ln -s /usr/bin/gcc ./gcc; \
	else \
		echo ">> ./gcc sudah ada."; \
	fi
	$(call install_pkg,json-c)
	$(call install_pkg,pkg-config)
	$(call install_pkg,json-c-devel)
	$(call install_pkg,python3)
	@if [ ! -e ./python ]; then \
		echo ">> Membuat symlink ./python..."; \
		$(USE_SUDO) ln -s /usr/bin/python3 ./python; \
	else \
		echo ">> ./python sudah ada."; \
	fi
endif	

dev:
	$(MAKE) libraries check_iwyu_h check_iwyu_c $(TARGET)
	@echo "-------------------------------------"
	@echo "orisium dikompilasi dalam mode DEVELOPMENT!"
	@echo "Executable: $(TARGET)"
	@echo "-------------------------------------"

prod:
	$(MAKE) libraries check_iwyu_h check_iwyu_c $(TARGET) BUILD_MODE=PRODUCTION
	@echo "-------------------------------------"
	@echo "orisium dikompilasi dalam mode PRODUCTION!"
	@echo "Executable: $(TARGET)"
	@echo "-------------------------------------"
	
$(TARGET): $(OBJS) \
	$(PQCLEAN_COMMON_OBJS) \
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
	@echo "Membangun dari sumber..."
	@if [ ! -f "$(PQCLEAN_SIGN_MLDSA87_LIB_PATH)" ]; then \
		$(MAKE) -C $(PQCLEAN_SIGN_MLDSA87_DIR); \
	else \
		echo "Library sudah ada: $@"; \
	fi

$(PQCLEAN_SIGN_FALCONPADDED512_LIB_PATH):
	@echo "Membangun Falcon-Padded-512..."
	@echo "Membangun dari sumber..."
	@if [ ! -f "$(PQCLEAN_SIGN_FALCONPADDED512_LIB_PATH)" ]; then \
		$(MAKE) -C $(PQCLEAN_SIGN_FALCONPADDED512_DIR); \
	else \
		echo "Library sudah ada: $@"; \
	fi

$(PQCLEAN_KEM_LIB_PATH):
	@echo "Membangun ML-KEM-1024..."
	@echo "Membangun dari sumber..."
	@if [ ! -f "$(PQCLEAN_KEM_LIB_PATH)" ]; then \
		$(MAKE) -C $(PQCLEAN_KEM_DIR); \
	else \
		echo "Library sudah ada: $@"; \
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
		$(MAKE) CC=../../../gcc -C $(LMDB_DIR); \
	fi

# =============================
# IWYU Check
# =============================
check_iwyu_c: $(IWYU_BIN_PATH)
	@echo "Menjalankan IWYU untuk *.c (kecuali: $(EXCLUDED_DIRS))..."
	@rm -f iwyu_failed_c.log iwyu_applied_c.log
	@for file in $(CFILES); do \
		echo "file: $$file"; \
		$(IWYU_BIN_PATH) $(FINAL_CFLAGS) "$$file" > /tmp/iwyu.tmp 2>&1; \
		if grep -q "should" /tmp/iwyu.tmp; then \
			echo "IWYU error in $$file" | tee -a iwyu_failed_c.log; \
			cat /tmp/iwyu.tmp >> iwyu_failed_c.log; \
			echo "" >> iwyu_failed_c.log; \
			./python $(IWYU_DIR)/fix_includes.py < /tmp/iwyu.tmp >> iwyu_applied_c.log 2>&1; \
			echo "FIX applied to $$file" >> iwyu_applied_c.log; \
		else \
			echo "Tidak ada masalah di $$file."; \
		fi; \
		rm -f /tmp/iwyu.tmp; \
	done; \
	if [ -f iwyu_failed_c.log ]; then \
		echo "IWYU sudah diperbaiki secara otomatis, log: iwyu_applied_c.log"; \
	else \
		echo "Semua file bersih dari masalah IWYU."; \
	fi
	
check_iwyu_h: $(IWYU_BIN_PATH)
	@echo "Menjalankan IWYU untuk *.h (kecuali: $(EXCLUDED_DIRS))..."
	@rm -f iwyu_failed_h.log iwyu_applied_h.log
	@for file in $(HFILES); do \
		echo "file: $$file"; \
		$(IWYU_BIN_PATH) $(FINAL_CFLAGS) "$$file" > /tmp/iwyu.tmp 2>&1; \
		if grep -q "should" /tmp/iwyu.tmp; then \
			echo "IWYU error in $$file" | tee -a iwyu_failed_h.log; \
			cat /tmp/iwyu.tmp >> iwyu_failed_h.log; \
			echo "" >> iwyu_failed_h.log; \
			./python $(IWYU_DIR)/fix_includes.py < /tmp/iwyu.tmp >> iwyu_applied_h.log 2>&1; \
			echo "FIX applied to $$file" >> iwyu_applied_h.log; \
		else \
			echo "Tidak ada masalah di $$file."; \
		fi; \
		rm -f /tmp/iwyu.tmp; \
	done; \
	if [ -f iwyu_failed_h.log ]; then \
		echo "IWYU sudah diperbaiki secara otomatis, log: iwyu_applied_h.log"; \
	else \
		echo "Semua file bersih dari masalah IWYU."; \
	fi

# =============================
# Bangun IWYU (jika belum ada)
# =============================
$(IWYU_BIN_PATH):
	@echo "Membangun IWYU..."
	@if [ ! -f "$(IWYU_BIN_PATH)" ]; then \
		echo "Membangun dari sumber..."; \
		echo "Memeriksa dan menginstall dependensi IWYU untuk distro $(DISTRO_ID) menggunakan $(PKG_MANAGER)..."; \
		if [ "$(PKG_MANAGER)" = "unsupported" ]; then \
			echo "Tidak bisa install dependensi. Distribusi tidak didukung."; \
			exit 1; \
		elif [ "$(PKG_MANAGER)" = "pkgin" ]; then \
			$(USE_SUDO) $(PKG_MANAGER) update && $(USE_SUDO) $(PKG_MANAGER) -y install wget cmake clang llvm; \
		elif [ "$(PKG_MANAGER)" = "pkg" ]; then \
			$(USE_SUDO) $(PKG_MANAGER) update && $(USE_SUDO) $(PKG_MANAGER) install -y wget cmake llvm; \
		elif [ "$(PKG_MANAGER)" = "pkg_add" ]; then \
			$(USE_SUDO) $(PKG_MANAGER) -u && $(USE_SUDO) $(PKG_MANAGER) wget gtar cmake; \
			CLLVMVER=$$(clang --version | head -n1 | sed 's/[^0-9]*\([0-9][0-9]*\)\..*/\1/'); \
			echo "================================"; \
			echo "!!--- PILIH llvm$$CLLVMVER ---!!"; \
			echo "================================"; \
			$(USE_SUDO) $(PKG_MANAGER) llvm; \
		elif [ "$(PKG_MANAGER)" = "dnf" ]; then \
			$(USE_SUDO) $(PKG_MANAGER) update && $(USE_SUDO) $(PKG_MANAGER) -y install wget cmake clang llvm clang-devel llvm-devel; \
		fi; \
		\
		CLANG_MAJOR_VER=$$(clang --version | head -n1 | sed 's/[^0-9]*\([0-9][0-9]*\)\..*/\1/'); \
		IWYU_VER=$$(expr $$CLANG_MAJOR_VER + 4); \
		echo "Deteksi Clang versi $$CLANG_MAJOR_VER"; \
		\
		LLVM_ROOT=$$(if [ "$(DISTRO_ID)" = "freebsd" ] || [ "$(DISTRO_ID)" = "openbsd" ]; \
			then echo "/usr/local/llvm$$CLANG_MAJOR_VER"; \
			else echo "/usr"; \
			fi); \
		LLVM_CMAKE_DIR=$$(if [ "$(DISTRO_ID)" = "freebsd" ] || [ "$(DISTRO_ID)" = "openbsd" ]; \
			then echo "$$LLVM_ROOT/lib/cmake/llvm"; \
			else echo "/usr/lib64/cmake/llvm"; \
			fi); \
		CLANG_CMAKE_DIR=$$(if [ "$(DISTRO_ID)" = "freebsd" ] || [ "$(DISTRO_ID)" = "openbsd" ]; \
			then echo "$$LLVM_ROOT/lib/cmake/clang"; \
			else echo ""; \
			fi); \
		\
		wget -q -O iwyu.tar.gz https://github.com/include-what-you-use/include-what-you-use/archive/refs/tags/0.$$IWYU_VER.tar.gz; \
		if [ "$(DISTRO_ID)" = "openbsd" ]; then \
			gtar -xzf iwyu.tar.gz -C iwyu --strip-components=1; \
		else \
			tar -xzf iwyu.tar.gz -C iwyu --strip-components=1; \
		fi; \
		rm -f iwyu.tar.gz && \
		cd $(IWYU_DIR) && \
		mkdir -p $(IWYU_BUILD) && \
		cd $(IWYU_BUILD) && \
		cmake \
		-G "Unix Makefiles" \
		-DCMAKE_C_COMPILER=clang \
		-DCMAKE_CXX_COMPILER=clang++ \
		-DCMAKE_BUILD_TYPE="Release" \
		-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DLLVM_DIR=$$LLVM_CMAKE_DIR \
		$$( [ -n "$$CLANG_CMAKE_DIR" ] && echo "-DClang_DIR=$$CLANG_CMAKE_DIR" ) \
		.. && \
		$(MAKE) -j2; \
	else \
		echo "IWYU sudah tersedia."; \
	fi

# =============================
# Targets tambahan
# =============================
clean:
	@echo "Membersihkan file objek dan executable..."
	rm -rf $(OBJ_DIR) $(TARGET)

run: $(TARGET)
	@echo "Menjalankan Orisium..."
	./$(TARGET)
	
debug: dev
	@echo "Menjalankan Orisium dalam mode debug..."
	./$(TARGET)

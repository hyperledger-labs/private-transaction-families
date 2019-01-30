######## SGX SDK Settings ########
SGX_MODE ?= HW
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -DSGX_ENCLAVE
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_CFLAGS += -O0 -g -DDEBUG
else
    SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
endif

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

######## Settings ########

Protected_Ledger_Root := ..
Common_Dir := $(Protected_Ledger_Root)/Common
ACL_Dir	   := $(Protected_Ledger_Root)/AccessControlLogic
SgxSsl_Dir := sgxssl

Crypto_CPP_Files := crypto.cpp crypto_aes.cpp crypto_ecdsa.cpp crypto_hash.cpp crypto_kdf.cpp crypto_kdf_enclave.cpp crypto_rand_engine.cpp crypto_ledger_reader_writer.cpp crypto_aes_siv.cpp crypto_stl_reader_writer_wrapper.cpp
Crypto_C_Objects :=  $(Crypto_CPP_Files:.cpp=.o)

Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(SgxSsl_Dir)/include

Crypto_Include_Paths := -I. -I$(Common_Dir) -I$(ACL_Dir) $(Enclave_Include_Paths)

Enclave_Common_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security -Wall -Wextra -Wconversion $(Crypto_Include_Paths)
ifneq ($(SGX_DEBUG), 1)
Enclave_Common_Flags += -fvisibility=hidden
else
Enclave_Common_Flags += -include tmemory_debug.h
endif

Enclave_C_Flags := $(Enclave_Common_Flags) -Wno-implicit-function-declaration -std=c11
Enclave_CXX_Flags := $(Enclave_Common_Flags) -std=c++11 -nostdinc++

.PHONY: all

all: stl_crypto_t.a

######## Build ########

%.o: %.cpp
	@$(CXX) $(Enclave_CXX_Flags) -c $< -o $@
	@echo "$(CXX)  <=  $<"

%.o: %.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "$(CC)  <=  $<"

stl_crypto_t.a: $(Crypto_C_Objects)
	ar rcs stl_crypto_t.a $(Crypto_C_Objects)
	@echo "ar =>  $@"

clean:
	@rm -f stl_crypto_t.a $(Crypto_C_Objects)


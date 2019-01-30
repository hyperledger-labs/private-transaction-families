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
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ENCLAVE_PATH := ../Enclave

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g -DDEBUG
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2 
endif



######## App Settings ########

Protected_Ledger_Root := ..
Crypto_Dir := $(Protected_Ledger_Root)/CryptoLib
SgxSsl_Dir := $(Crypto_Dir)/sgxssl
Main_Dir := $(Protected_Ledger_Root)/Main

App_CPP_Files := enclave_log.cpp enclave_role.cpp ledger_keys.cpp tmemory_leaks.cpp PrivateLedger.cpp config.cpp safe_copy.cpp cJSON.cpp

App_Objects := $(App_CPP_Files:.cpp=.o)

App_Include_Paths := -I. -I$(SGX_SDK)/include  -I$(Main_Dir)/Enclave -I$(Crypto_Dir) -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(SgxSsl_Dir)/include -I$(Common_Dir) -I$(ACL_Dir)

App_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security -Wall -Wextra -Wconversion $(App_Include_Paths)

ifneq ($(SGX_DEBUG), 1)
App_C_Flags += -fvisibility=hidden
endif

App_CXX_Flags := $(App_C_Flags) -std=c++11


.PHONY: all clean

all: libcommon_t.a

######## App Objects ########

Enclave_t.c: 
	$(MAKE) -C $(Main_Dir)/Enclave -f generate_edge_files_t.mk 

%.o: %.cpp
	@$(CXX) $(App_CXX_Flags) -c $< -o $@
	@echo "$(CXX)  <=  $<"

%.o: %.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "$(CC)  <=  $<"

libcommon_t.a: Enclave_t.c $(App_Objects)
	ar rcs libcommon_t.a $(App_Objects)
	@echo "ar =>  $@"

clean:
	@rm -f libcommon_t.a $(App_Objects)
	


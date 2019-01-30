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
ACL_Dir := $(Protected_Ledger_Root)/AccessControlLogic
Crypto_Dir := $(Protected_Ledger_Root)/CryptoLib
SgxSsl_Dir := $(Crypto_Dir)/sgxssl
Main_Dir := $(Protected_Ledger_Root)/Main

Enclave_C_Files := $(wildcard *.c) 
Enclave_CPP_Files := $(wildcard *.cpp) 


Enclave_C_Objects := $(Enclave_C_Files:.c=.o)
Enclave_C_Objects +=  $(Enclave_CPP_Files:.cpp=.o)
#
Enclave_Include_Paths := -I. -I$(Common_Dir) -I$(ACL_Dir) -I$(Crypto_Dir) -I$(SgxSsl_Dir)/include \
-I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc

Enclave_Common_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security -Wall $(Enclave_Include_Paths)


ifneq ($(SGX_DEBUG), 1)
App_Common_Flags += -fvisibility=hidden
else
Enclave_Common_Flags += -include $(Common_Dir)/tmemory_debug.h
endif

Enclave_C_Flags := $(Enclave_Common_Flags) -Wno-implicit-function-declaration -std=c11
Enclave_CXX_Flags := $(Enclave_Common_Flags) -std=c++11 -nostdinc++

       
.PHONY: all

all: libbusiness_logic.a

######## Build ########

$(Main_Dir)/Enclave/Enclave_t.h: 
	$(MAKE) -C $(Main_Dir)/Enclave -f generate_edge_files_t.mk 

%.o: %.cpp
	@$(CXX) $(Enclave_CXX_Flags) -c $< -o $@
	@echo "$(CXX)  <=  $<"

%.o: %.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "$(CC)  <=  $<"

libbusiness_logic.a: $(Main_Dir)/Enclave/Enclave_t.h $(Enclave_C_Objects)
	ar rcs libbusiness_logic.a $(Enclave_C_Objects)
	@echo "ar =>  $@"

clean:
	@rm -f libbusiness_logic.a $(Enclave_C_Objects)


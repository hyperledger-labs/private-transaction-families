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
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ENCLAVE_PATH := ../enclave

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g -DDEBUG
        Binary_Folder := debug
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
        Binary_Folder := release
endif


######## App Settings ########

Protected_Ledger_Root := ../../..
Network_Dir := $(Protected_Ledger_Root)/Network
Common_Dir := $(Protected_Ledger_Root)/Common
Crypto_Dir := $(Protected_Ledger_Root)/CryptoLib
SgxSsl_Dir := $(Crypto_Dir)/sgxssl

ifeq ($(PERFORMANCE), 1)
SGX_COMMON_CFLAGS += -DPERFORMANCE
endif

App_C_Files := $(wildcard *.c)
App_CPP_Files := $(wildcard *.cpp) $(Network_Dir)/network.cpp $(Network_Dir)/server_network.cpp $(Common_Dir)/common_ocalls.cpp
App_C_Objects := $(App_C_Files:.c=.o) $(App_CPP_Files:.cpp=.o)

App_Include_Paths := -I. -I$(Crypto_Dir) -I$(Crypto_Dir)/openssl/include -I$(Common_Dir) -I$(Network_Dir) -I$(SGX_SDK)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fpic -fpie -fstack-protector -Wformat -Wformat-security -Wall -Wextra -Wconversion -Wno-attributes $(App_Include_Paths)

App_CXX_Flags := $(App_C_Flags) -std=c++11


ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
	UaeService_Library_Name := sgx_uae_service_sim
else
	Urts_Library_Name := sgx_urts
	UaeService_Library_Name := sgx_uae_service
endif

Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

ifeq ($(SGX_DEBUG), 1)
	SGXSSL_LIB := sgx_usgxssld
else
	SGXSSL_LIB := sgx_usgxssl
endif
SgxSsl_Link_Files := -L$(SgxSsl_Dir)/lib64/ -l$(SGXSSL_LIB)

App_Link_Flags := $(SGX_COMMON_CFLAGS) $(Security_Link_Flags) \
				-L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -l$(UaeService_Library_Name) -lsgx_ukey_exchange -lpthread \
				$(SgxSsl_Link_Files)


ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

all: app

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/App
	@echo "RUN  =>  App [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

Enclave_u.c: $(SGX_EDGER8R) ../enclave/Enclave.edl
	$(SGX_EDGER8R) --untrusted ../enclave/Enclave.edl --search-path $(ENCLAVE_PATH) --search-path $(SgxSsl_Dir)/include --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave_u.o: Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "$(CC)   <=  $<"

%.o: %.cpp
	@$(CXX) $(App_CXX_Flags) -c $< -o $@
	@echo "$(CXX)  <=  $<"

%.o: %.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "$(CC)  <=  $<"

app: Enclave_u.o $(App_C_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean

clean:
	@rm -f app $(App_C_Objects) Enclave_u.* 
	

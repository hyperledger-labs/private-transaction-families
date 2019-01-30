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
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_CFLAGS += -O0 -g -DDEBUG
    BIN_FOLDER := debug
else
    SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
    BIN_FOLDER := release
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

######## Enclave Settings ########

Protected_Ledger_Root := ../..
Acl_Dir := $(Protected_Ledger_Root)/AccessControlLogic
Common_Dir := $(Protected_Ledger_Root)/Common
Bl_Dir := $(Protected_Ledger_Root)/BusinessLogic
Crypto_Dir := $(Protected_Ledger_Root)/CryptoLib
SgxSsl_Dir := $(Crypto_Dir)/sgxssl
Client_reader_Dir := $(Protected_Ledger_Root)/ClientReader
Lib_Dir := $(Protected_Ledger_Root)/lib
Listener_Dir := $(Protected_Ledger_Root)/Listener

Enclave_C_Files := $(wildcard *.c) 
Enclave_CPP_Files := $(wildcard *.cpp) \
$(Client_reader_Dir)/Server/enclave/tclient_reader.cpp \
$(Client_reader_Dir)/Server/enclave/tenclave_read.cpp \

Enclave_C_Objects := $(Enclave_C_Files:.c=.o)
Enclave_C_Objects +=  $(Enclave_CPP_Files:.cpp=.o)

Enclave_Include_Paths := -I. -I$(Common_Dir) -I$(Client_reader_Dir) -I$(Acl_Dir) -I$(Bl_Dir) -I$(Crypto_Dir) -I$(SgxSsl_Dir)/include \
-I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc 


Enclave_Common_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fpic -fpie -fstack-protector -fno-builtin-printf -Wall -Wformat -Wformat-security -Werror $(Enclave_Include_Paths)
ifneq ($(SGX_DEBUG), 1)
Enclave_Common_Flags += -fvisibility=hidden
endif

Enclave_C_Flags := $(Enclave_Common_Flags) -Wno-implicit-function-declaration -std=c11
Enclave_CXX_Flags := $(Enclave_Common_Flags) -std=c++11 -nostdinc++

Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie
ifeq ($(SGX_DEBUG), 1)
	SGXSSL_LIB := sgx_tsgxssld
    SGXSSL_CRYPTO_LIB := sgx_tsgxssl_cryptod
    SGXSSL_SSL_LIB := sgx_tsgxssl_ssld
	AES_SIV_LIB := aes_sivd
else
	SGXSSL_LIB := sgx_tsgxssl
    SGXSSL_CRYPTO_LIB := sgx_tsgxssl_crypto
    SGXSSL_SSL_LIB := sgx_tsgxssl_ssl
	AES_SIV_LIB := aes_siv
endif
SgxSsl_Link_Files := -L$(SgxSsl_Dir)/lib64 -Wl,--whole-archive -l$(SGXSSL_LIB) -Wl,--no-whole-archive -l$(SGXSSL_SSL_LIB) -l$(SGXSSL_CRYPTO_LIB) -l$(AES_SIV_LIB)

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	$(Security_Link_Flags) -L$(Lib_Dir)/$(BIN_FOLDER) -lbusiness_logic -lserver_sync_t -lcommon_t -lacl -llistener_t -lstl_crypto_t \
	$(SgxSsl_Link_Files) -L$(SGX_LIBRARY_PATH) -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tkey_exchange -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=Enclave.lds

.PHONY: all run

all: Enclave.signed.so
# usually release mode don't sign the enclave, but here we want to run the test also in release mode
# this is not realy a release mode as the XML file don't disable debug - we can't load real release enclaves (white list)

run: all


######## TestEnclave Objects ########

Enclave_t.c: 
	$(MAKE) -C . -f generate_edge_files_t.mk 

Enclave_t.o: Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

%.o: %.cpp
	@$(CXX) $(Enclave_CXX_Flags) -c $< -o $@
	@echo "CC  <=  $<"

%.o: %.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

Enclave.so: Enclave_t.o $(Enclave_C_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

Enclave.signed.so: Enclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave_private.pem -enclave Enclave.so -out $@ -config Enclave.config.xml
	@echo "SIGN =>  $@"

clean:
	@rm -f Enclave.o Enclave.so Enclave.signed.so Enclave_t.* $(Enclave_C_Objects)


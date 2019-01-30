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

ENCLAVE_PATH := ../Enclave

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g -DDEBUG
		BIN_FOLDER := debug
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
		BIN_FOLDER := release
endif


######## App Settings ########

Protected_Ledger_Root := ../..
Common_Dir := $(Protected_Ledger_Root)/Common
Crypto_Dir := $(Protected_Ledger_Root)/CryptoLib
Sawtooth_Dir := $(Protected_Ledger_Root)/../sawtooth-sdk-cxx
SgxSsl_Dir := $(Crypto_Dir)/sgxssl
Network_Dir := $(Protected_Ledger_Root)/Network
Client_reader_Dir := $(Protected_Ledger_Root)/ClientReader
Listener_App_Dir := $(Protected_Ledger_Root)/Listener/App
Lib_Dir := $(Protected_Ledger_Root)/lib

App_C_Files := $(wildcard *.c) 
App_CPP_Files := $(wildcard *.cpp) $(Network_Dir)/network.cpp $(Network_Dir)/server_network.cpp $(Client_reader_Dir)/Server/app/client_reader.cpp

App_C_Objects := $(App_C_Files:.c=.o) $(App_CPP_Files:.cpp=.o)

App_Include_Paths := -I. -I$(Common_Dir) -I$(Client_reader_Dir)/Common -I$(Listener_App_Dir) -I$(Network_Dir) -I$(Crypto_Dir) -I$(Crypto_Dir)/openssl/include \
-I$(SGX_SDK)/include -I$(Protected_Ledger_Root)/build -I$(Sawtooth_Dir)/include 

App_C_Flags := $(SGX_COMMON_CFLAGS) -fstack-protector -Wall -Wformat -Wformat-security -Wno-attributes -Werror $(App_Include_Paths)

App_CXX_Flags := $(App_C_Flags) -std=c++11

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
	UaeService_Library_Name := sgx_uae_service_sim
else
	Urts_Library_Name := sgx_urts
	UaeService_Library_Name := sgx_uae_service
endif

Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now 
OpenSsl_Link_Files := -L$(Crypto_Dir)/openssl/lib -lssl -lcrypto
sawtooth_Link_Fils := -L$(Sawtooth_Dir)/build/lib -lsawtooth -lproto
ifeq ($(SGX_MODE), HW)
	sawtooth_Link_Fils += /usr/lib/libprotobuf.a
else
	sawtooth_Link_Fils += -L/usr/local/lib -L/usr/lib -lprotobuf
endif
sawtooth_Link_Fils += -lzmq -lzmqpp -llog4cxx -lcryptopp -lpthread

ifeq ($(SGX_DEBUG), 1)
	SGXSSL_LIB := sgx_usgxssld
else
	SGXSSL_LIB := sgx_usgxssl
endif
SgxSsl_Link_Files := -L$(SgxSsl_Dir)/lib64/ -l$(SGXSSL_LIB)


App_Link_Flags := $(SGX_COMMON_CFLAGS) $(Security_Link_Flags) $(SgxSsl_Link_Files) \
	-L$(Lib_Dir)/$(BIN_FOLDER) -llistener_u -lcommon_u \
	-L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -l$(UaeService_Library_Name) \
	$(OpenSsl_Link_Files) $(sawtooth_Link_Fils) -lcurl -lstdc++ 


ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run clean

all: private-tp

run: all

######## App Objects ########

Enclave_u.c: 
	$(MAKE) -C . -f App/generate_edge_files_u.mk 

Enclave_u.o: Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "$(CC)   <=  $<"

%.o: %.cpp
	@$(CXX) $(App_CXX_Flags) -c $< -o $@
	@echo "$(CXX)  <=  $<"

%.o: %.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "$(CC)  <=  $<"

private-tp: Enclave_u.o $(App_C_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -f private-tp $(App_C_Objects) Enclave_u.* 
		#@rm -f App $(App_C_Objects) Enclave_u.* 
	

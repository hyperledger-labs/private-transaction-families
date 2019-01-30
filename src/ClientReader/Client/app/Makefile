######## General Settings ########

ifeq ($(DEBUG), 1)
        COMMON_CFLAGS += -O0 -g -DDEBUG
        Binary_Folder := debug
else
        COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
        Binary_Folder := release
endif

######## App Settings ########

Protected_Ledger_Root := ../../..
Network_Dir := $(Protected_Ledger_Root)/Network
Crypto_Dir := $(Protected_Ledger_Root)/CryptoLib
Common_Dir := $(Protected_Ledger_Root)/Common
Libraries_Dir := $(Protected_Ledger_Root)/lib

ifeq ($(PERFORMANCE), 1)
COMMON_CFLAGS += -DPERFORMANCE
endif

App_C_Files := $(wildcard *.c)
App_CPP_Files := $(wildcard *.cpp) $(Network_Dir)/client_network.cpp
App_C_Objects := $(App_C_Files:.c=.o) $(App_CPP_Files:.cpp=.o)

App_Include_Paths := -I. -I$(Network_Dir) -I$(Crypto_Dir) -I$(Crypto_Dir)/openssl/include -I$(Common_Dir)

App_C_Flags := $(COMMON_CFLAGS) -fpic -fpie -fstack-protector -Wformat -Wformat-security -Wall -Wextra -Wconversion -Wno-attributes $(App_Include_Paths)

App_CXX_Flags := $(App_C_Flags) -std=c++11

Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie
ifeq ($(DEBUG), 1)
	OPENSSL_SSL_LIB := ssld
	OPENSSL_CRYPTO_LIB := cryptod
else
	OPENSSL_SSL_LIB := ssl
	OPENSSL_CRYPTO_LIB := crypto
endif
OpenSsl_Link_Files := -L$(Crypto_Dir)/openssl/lib -l$(OPENSSL_SSL_LIB) -l$(OPENSSL_CRYPTO_LIB)

App_Link_Flags := $(COMMON_CFLAGS) $(Security_Link_Flags) -lpthread -L$(Libraries_Dir)/$(Binary_Folder) -lstl_crypto_u $(OpenSsl_Link_Files)

.PHONY: all run

all: app

run: all

######## App Objects ########

%.o: %.cpp
	@$(CXX) $(App_CXX_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

%.o: %.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

app: $(App_C_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean

clean:
	@rm -f app $(App_C_Objects)
	

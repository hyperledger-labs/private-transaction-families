######## General Settings ########
ifeq ($(DEBUG), 1)
    COMMON_CFLAGS += -O0 -g -DDEBUG
else
    COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
endif

ifeq ($(SKIP_SIGN), 1)
    COMMON_CFLAGS += -DSKIP_SIGN
else
ifeq ($(HSM_SIGN), 1)
    COMMON_CFLAGS += -DHSM_SIGN
endif
endif

######## Settings ########

Protected_Ledger_Root := ..
Common_Dir := $(Protected_Ledger_Root)/Common

Crypto_Dir := $(Protected_Ledger_Root)/CryptoLib

OpenSsl_Dir := $(Crypto_Dir)/openssl



Crypto_CPP_Files := $(Common_Dir)/safe_copy.cpp crypto.cpp crypto_aes.cpp crypto_ecdsa.cpp crypto_hash.cpp crypto_kdf.cpp crypto_files.cpp crypto_ledger_reader_writer.cpp crypto_stl_reader_writer_python_wrapper.cpp
Crypto_C_Files := $(Common_Dir)/memset_s.c
Crypto_C_Objects := $(Crypto_C_Files:.c=.o) $(Crypto_CPP_Files:.cpp=.o)

App_Include_Paths := -I$(OpenSsl_Dir)/include 

Crypto_Include_Paths := -I. -I$(Common_Dir) $(App_Include_Paths)

App_Common_Flags := $(COMMON_CFLAGS) -shared -fPIE -fPIC -fstack-protector -Wformat -Wformat-security -Wall $(Crypto_Include_Paths)

App_C_Flags := $(App_Common_Flags) -Wno-implicit-function-declaration -std=c11 -shared

OpenSsl_Link_Files := -L$(OpenSsl_Dir)/lib -lcrypto

App_CXX_Flags := $(App_Common_Flags) -std=c++11 

.PHONY: all

all: stl_crypto_u.so

######## Build ########

%.o: %.cpp
	@$(CXX) $(App_CXX_Flags) -c $< -o $@
	@echo "$(CXX)  <=  $<"

%.o: %.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "$(CC)  <=  $<"

stl_crypto_u.so: $(Crypto_C_Objects)
	@$(CXX) $(App_CXX_Flags) -o $@  $(Crypto_C_Objects) -shared $(OpenSsl_Link_Files)
	@echo "$(CXX) =>  $@"

clean:
	@rm -f stl_crypto_u.so $(Crypto_C_Objects)


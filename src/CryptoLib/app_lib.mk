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
OpenSsl_Dir := openssl

Crypto_CPP_Files := crypto.cpp crypto_aes.cpp crypto_ecdsa.cpp crypto_hash.cpp crypto_kdf.cpp crypto_files.cpp crypto_ledger_reader_writer.cpp crypto_stl_reader_writer_python_wrapper.cpp
Crypto_C_Objects :=  $(Crypto_CPP_Files:.cpp=.o)

App_Include_Paths := -I$(OpenSsl_Dir)/include 

Crypto_Include_Paths := -I. -I$(Common_Dir) $(App_Include_Paths)

App_Common_Flags := $(COMMON_CFLAGS) -fpic -fpie -fstack-protector -Wformat -Wformat-security -Wall -Wextra -Wconversion $(Crypto_Include_Paths)
ifneq ($(SGX_DEBUG), 1)
App_Common_Flags += -fvisibility=hidden
endif

App_C_Flags := $(App_Common_Flags) -Wno-implicit-function-declaration -std=c11
App_CXX_Flags := $(App_Common_Flags) -std=c++11

.PHONY: all

all: stl_crypto_u.a

######## Build ########

%.o: %.cpp
	@$(CXX) $(App_CXX_Flags) -c $< -o $@
	@echo "$(CXX)  <=  $<"

%.o: %.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "$(CC)  <=  $<"

stl_crypto_u.a: $(Crypto_C_Objects)
	ar rcs stl_crypto_u.a $(Crypto_C_Objects)
	@echo "ar =>  $@"

clean:
	@rm -f stl_crypto_u.a $(Crypto_C_Objects)


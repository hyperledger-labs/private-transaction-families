
ifeq ($(DEBUG), 1)
        COMMON_CFLAGS += -O0 -g -DDEBUG
else
        COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
endif


######## App Settings ########

Protected_Ledger_Root := ..
Crypto_Dir := $(Protected_Ledger_Root)/CryptoLib
Main_Dir := $(Protected_Ledger_Root)/Main

App_C_Files := memset_s.c
App_CPP_Files := common_ocalls.cpp safe_copy.cpp config.cpp

App_Objects := $(App_C_Files:.c=.o) $(App_CPP_Files:.cpp=.o)

App_Include_Paths := -I. -I$(Main_Dir)/App -I$(SGX_SDK)/include -I$(Crypto_Dir) 

App_C_Flags := $(COMMON_CFLAGS) -fstack-protector -Wall -Wformat -Wformat-security -Wno-attributes -Werror $(App_Include_Paths)

App_CXX_Flags := $(App_C_Flags) -std=c++11


.PHONY: all 

all: libcommon_u.a

######## App Objects ########

$(Main_Dir)/App/Enclave_u.h: 
	$(MAKE) -C $(Main_Dir)/App -f generate_edge_files_u.mk 

%.o: %.cpp
	@$(CXX) $(App_CXX_Flags) -c $< -o $@
	@echo "$(CXX) <=  $<"

%.o: %.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "$(CC)  <=  $<"

libcommon_u.a: $(Main_Dir)/App/Enclave_u.h $(App_Objects)
	ar rcs libcommon_u.a $(App_Objects)
	@echo "ar =>  $@"

.PHONY: clean

clean:
	@rm -f libcommon_u.a $(App_Objects)
	


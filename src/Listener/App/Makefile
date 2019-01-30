
ifeq ($(DEBUG), 1)
        COMMON_CFLAGS += -O0 -g -DDEBUG
else
        COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
endif


Protected_Ledger_Root := ../..
Common_Dir := $(Protected_Ledger_Root)/Common
Sawtooth_Dir := $(Protected_Ledger_Root)/../sawtooth-sdk-cxx
Main_dir := $(Protected_Ledger_Root)/Main



App_CPP_Files := $(wildcard *.cpp)

App_Objects := $(App_CPP_Files:.cpp=.o)

App_Include_Paths := -I. -I$(Main_dir)/App -I$(Common_Dir) -I$(Sawtooth_Dir)/include -I$(SGX_SDK)/include 

App_C_Flags := $(COMMON_CFLAGS) -fstack-protector -fPIC -Wall -Wformat -Wformat-security -Wno-attributes -Werror $(App_Include_Paths)

App_CXX_Flags := $(App_C_Flags) -std=c++11 


.PHONY: all

all: liblistener_u.a

%.o: %.cpp
	@$(CXX) $(App_CXX_Flags) -c $< -o $@
	@echo "$(CXX)  <=  $<"

%.o: %.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "$(CC)  <=  $<"

liblistener_u.a: $(App_Objects)
	ar rcs liblistener_u.a $(App_Objects)
	@echo "ar =>  $@"


.PHONY: clean

clean:
	@rm -f liblistener_u.a $(App_Objects) 
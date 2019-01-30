
.PHONY: all clean

all:

ifeq ($(SGX_DEBUG), 1)
	$(MAKE) -f bl_lib.mk $(MFLAGS)
	mv libbusiness_logic.a ../lib/debug/libbusiness_logic.a
	$(MAKE) -f bl_lib.mk $(MFLAGS) clean

else	
	$(MAKE) -f bl_lib.mk $(MFLAGS)
	mv libbusiness_logic.a ../lib/release/libbusiness_logic.a
	$(MAKE) -f bl_lib.mk $(MFLAGS) clean
endif

clean:
	rm -f ../lib/debug/libbusiness_logic.a  ../lib/release/libbusiness_logic.a
	$(MAKE) -f bl_lib.mk $(MFLAGS) clean


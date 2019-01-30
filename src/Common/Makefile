
.PHONY: all clean

all:
ifeq ($(SGX_DEBUG), 1)
	$(MAKE) -f common_t.mk 
	mv libcommon_t.a ../lib/debug/libcommon_t.a
	$(MAKE) -f common_t.mk clean
		
	$(MAKE) -f common_u.mk DEBUG=1
	mv libcommon_u.a ../lib/debug/libcommon_u.a
	$(MAKE) -f common_u.mk clean

else
	$(MAKE) -f common_t.mk 
	mv libcommon_t.a ../lib/release/libcommon_t.a
	$(MAKE) -f common_t.mk clean
		
	$(MAKE) -f common_u.mk 
	mv libcommon_u.a ../lib/release/libcommon_u.a
	$(MAKE) -f common_u.mk clean
endif

	
clean:
	rm -f ../lib/debug/libcommon_t.a ../lib/debug/libcommon_u.a ../lib/release/libcommon_t.a ../lib/release/libcommon_u.a
	$(MAKE) -f common_t.mk clean
	$(MAKE) -f common_u.mk clean

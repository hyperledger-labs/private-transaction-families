
.PHONY: all clean

all:
ifeq ($(SGX_DEBUG), 1)
	$(MAKE) -f acl_lib.mk $(MFLAGS)
	mv libacl.a ../lib/debug/libacl.a
	$(MAKE) -f acl_lib.mk $(MFLAGS) clean

else	
	$(MAKE) -f acl_lib.mk $(MFLAGS)
	mv libacl.a ../lib/release/libacl.a
	$(MAKE) -f acl_lib.mk $(MFLAGS) clean
	
endif

clean:
	rm -f ../lib/debug/libacl.a  ../lib/release/libacl.a
	$(MAKE) -f acl_lib.mk $(MFLAGS) clean



.PHONY: all clean

all:
	$(shell mkdir -p ~/.stl_keys)

ifeq ($(SGX_DEBUG), 1)
	$(MAKE) -C Enclave $(MFLAGS)
	mv Enclave/liblistener_t.a ../lib/debug/liblistener_t.a
	$(MAKE) -C Enclave $(MFLAGS) clean
	$(MAKE) -C App DEBUG=1
	mv App/liblistener_u.a ../lib/debug/liblistener_u.a
	$(MAKE) -C App $(MFLAGS) clean
else
	$(MAKE) -C Enclave $(MFLAGS)
	mv Enclave/liblistener_t.a ../lib/release/liblistener_t.a
	$(MAKE) -C Enclave $(MFLAGS) clean
	$(MAKE) -C App 
	mv App/liblistener_u.a ../lib/release/liblistener_u.a
	$(MAKE) -C App $(MFLAGS) clean
endif

clean:	
	rm -f ../lib/debug/liblistener_t.a ../lib/debug/liblistener_u.a ../lib/release/liblistener_t.a ../lib/release/liblistener_u.a
	$(MAKE) -C Enclave clean
	$(MAKE) -C App clean


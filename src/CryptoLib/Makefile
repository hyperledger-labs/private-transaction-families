
.PHONY: all clean

all: clean
# static trusted library, debug
	$(MAKE) -f enclave_lib.mk SGX_DEBUG=1
	mv stl_crypto_t.a ../lib/debug/libstl_crypto_t.a
	$(MAKE) -f enclave_lib.mk $(MFLAGS) clean

# static untrusted library, debug	
	$(MAKE) -f app_lib.mk DEBUG=1
	mv stl_crypto_u.a ../lib/debug/libstl_crypto_u.a
	$(MAKE) -f app_lib.mk $(MFLAGS) clean

# static trusted library, release
	$(MAKE) -f enclave_lib.mk
	mv stl_crypto_t.a ../lib/release/libstl_crypto_t.a
	$(MAKE) -f enclave_lib.mk $(MFLAGS) clean

# static untrusted library, release	
	$(MAKE) -f app_lib.mk
	mv stl_crypto_u.a ../lib/release/libstl_crypto_u.a
	$(MAKE) -f app_lib.mk $(MFLAGS) clean

# shared untrusted library, debug
	$(MAKE) -f app_shared_lib.mk DEBUG=1
	mv stl_crypto_u.so ../lib/debug/libstl_crypto_so_u.so
	$(MAKE) -f app_shared_lib.mk $(MFLAGS) clean

# shared untrusted library, release
	$(MAKE) -f app_shared_lib.mk
	mv stl_crypto_u.so ../lib/release/libstl_crypto_so_u.so
	$(MAKE) -f app_shared_lib.mk $(MFLAGS) clean

	
clean:
	rm -f ../lib/debug/libstl_crypto_u.a ../lib/debug/libstl_crypto_t.a ../lib/debug/libstl_crypto_so_u.so
	rm -f ../lib/release/libstl_crypto_u.a ../lib/release/libstl_crypto_t.a ../lib/release/libstl_crypto_so_u.so 
	$(MAKE) -f enclave_lib.mk $(MFLAGS) clean
	$(MAKE) -f app_lib.mk $(MFLAGS) clean
	$(MAKE) -f app_shared_lib.mk $(MFLAGS) clean
	

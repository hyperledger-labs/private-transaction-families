
.PHONY: all clean

all:
	$(MAKE) -C enclave all
	$(MAKE) -C app all
	cp enclave/Enclave.signed.so .
	cp app/app client_reader_app

clean:	
	$(MAKE) -C enclave clean
	$(MAKE) -C app clean
	rm -f Enclave.signed.so
	rm -f client_reader_app


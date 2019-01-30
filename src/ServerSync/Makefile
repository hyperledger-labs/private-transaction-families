
.PHONY: all standalone clean

standalone:
	$(MAKE) -C enclave full_enclave
	cp enclave/Enclave.signed.so .
	$(MAKE) -C enclave clean_common # clean it because enclave and app use common files
	
	$(MAKE) -C app all
	cp app/keys_creation keys_creation
	cp app/keys_server keys_server
	cp app/keys_client keys_client
		
	$(MAKE) -C tools all
	cp tools/kds_calculator kds_calculator
	cp tools/kds_signer kds_signer
	cp tools/client_keys_creator client_keys_creator
	
	$(MAKE) -C app clean_common

all:
	$(MAKE) -C enclave library # will also copy the library to the binary folder
	
	$(MAKE) -C app all
	cp app/keys_creation ../../out/
	cp app/keys_server ../../out/
	cp app/keys_client ../../out/
	
	$(MAKE) -C tools all
	cp tools/kds_calculator ../../out/
	cp tools/kds_signer ../../out/
	cp tools/client_keys_creator ../../out/
	
clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C app clean
	$(MAKE) -C tools clean
	rm -f Enclave.signed.so
	rm -f keys_creation kds_signer keys_server keys_client kds_calculator client_keys_creator
	rm -f ../../out/keys_creation ../../out/kds_signer ../../out/keys_server ../../out/keys_client ../../out/kds_calculator ../../out/client_keys_creator


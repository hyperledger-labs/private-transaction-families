######## SGX SDK Settings ########

SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

######## Settings ########

Protected_Ledger_Root := ../..
Crypto_Dir := $(Protected_Ledger_Root)/CryptoLib
SgxSsl_Dir := $(Crypto_Dir)/sgxssl
Main_Dir := $(Protected_Ledger_Root)/Main
       
.PHONY: all

all: generated_edge_files

######## Build ########

generated_edge_files: $(SGX_EDGER8R) 
	$(SGX_EDGER8R) --trusted $(Main_Dir)/Enclave/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(SgxSsl_Dir)/include 
	@echo "GEN  =>  $@"

clean:
	@rm -f Enclave_t.h Enclave_t.c


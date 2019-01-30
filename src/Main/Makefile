
.PHONY: all clean

all:
	#$(shell mkdir -p ~/.stl_keys)
	
	$(MAKE) -C ../CryptoLib all
	$(MAKE) -C ../Common all
	$(MAKE) -C ../BusinessLogic all
	$(MAKE) -C ../AccessControlLogic all
	$(MAKE) -C ../Listener all
	$(MAKE) -C ../ServerSync all
	$(MAKE) -C App -f app.mk all
	$(MAKE) -C Enclave -f Enclave.mk all
	cp Enclave/Enclave.signed.so ../../out/
	cp App/private-tp ../../out/


clean:
	$(MAKE) -C ../CryptoLib clean
	$(MAKE) -C ../ServerSync clean
	$(MAKE) -C ../Listener clean
	$(MAKE) -C ../BusinessLogic clean
	$(MAKE) -C ../AccessControlLogic clean
	$(MAKE) -C ../Common clean
	$(MAKE) -C Enclave -f Enclave.mk clean
	$(MAKE) -C App -f app.mk clean
	rm -f ../../out/Enclave.signed.so ../../out/private-tp


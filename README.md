# Private Transaction Families

## Short Description

Private-transaction-families system is a preview release which provides a 
mechanism for privacy over Hyperledger Sawtooth by enforcing a policy of 
access control to the ledger.

This project provides benefits for both application developers seeking to 
define and implement privacy-preserving distributed ledgers, and for service 
providers seeking to provide blockchain services with access restriction to 
the ledger data

## Scope of Lab

The system is based on a generic distributed ledger infrastructure 
(Hyperledger Sawtooth) and an Intel® SGX (Software Guard Extensions) 
'hardened' Transaction Processor which provides a mechanism to enable 
Hyperledger Sawtooth to contain private information that is both not publicly
available but required to validate transactions.

This solution supports encryption of information in transactions and blocks 
while allowing the ledger to validate the information in those transactions in 
all the nodes and allow them to reach a consensus on the current state of the 
ledger. The system can be tested on a single node or multi nodes.

Private-transaction-families operates as a project in Hyperledger Labs which 
provides a channel suitable for innovation and collaboration where virtual 
teams can experiment with new frameworks and new modules without the promise of
stable code or MVP. As such, Private-transaction-families is provided as a 
developer preview (Alpha) to demonstrate how privacy can be deployed on top of 
Hyperledger Sawtooth.

## Documentation

Instructions for installing/building Hyperledger Private Transaction Families
can be found in the [SETUP](SETUP.md) documentation.

The [USAGE](USAGE.md) document describes how to submit encrypted transaction
and submit encrypted read requests

For more information about how Private Transaction Families work, see the
[SPECIFICATION](SPECIFICATION.md) document.

  
## Initial Committers

- [Yoni Wolf](https://github.com/yoni-wolf)
- [Ishai Nadler](https://github.com/naishai)
- [Shefy Gurary](https://github.com/sgurary)
- [Ronen Shem-tov](https://github.com/ronenshemtov)
- [Edan Sorski](https://github.com/esorski)
- [Oron Lenz](mailto:oron.lenz@intel.com)
- [Guy Itzhaki](mailto:guy.itzhaki@intel.com)

  
## Sponsor

 - [Dan Middleton](https://github.com/dcmiddle)

  
## License

Private-transaction-families software is released under the Apache License 
Version 2.0 software license. See the [license](LICENSE) file for more details.


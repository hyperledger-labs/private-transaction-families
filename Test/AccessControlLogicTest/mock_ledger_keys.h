///////////////////////////////////////////////////////
// mock of ACL code
///////////////////////////////////////////////////////
#include "ledger_keys.h"

Ledger_Keys_Manager::Ledger_Keys_Manager()
{
}

Ledger_Keys_Manager::~Ledger_Keys_Manager()
{
}

bool Ledger_Keys_Manager::keys_ready()
{
    return true;
}

uint16_t Ledger_Keys_Manager::get_svn()
{
    return 1;
}

const ledger_keys_t *Ledger_Keys_Manager::get_ledger_keys_by_svn(uint16_t svn)
{
    ledger_keys_t *lk;
    memset(lk, 7, sizeof(ledger_keys_t));
    return lk;
}

const kdf32_key_t *Ledger_Keys_Manager::get_kds_by_svn(uint16_t svn)
{
    kdf32_key_t *lk;
    memset(lk, 7, sizeof(kdf32_key_t));
    return lk;
}

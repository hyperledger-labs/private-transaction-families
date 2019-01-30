///////////////////////////////////////////////////////
// mock of ACL code
///////////////////////////////////////////////////////

#include "access_control.h"

Result acl_allow_access(const StlAddress &addr, const Key &PublicKey){}
bool acl_has_access(const StlAddress &addr, const Key &key){}
bool acl_read(const StlAddress &addr, const Key &key, secure::string* out_value, bool is_client_reader)){}
Result acl_write(const StlAddress &addr, const Key &key, const secure::string &buffer){}
Result acl_set_public(const StlAddress &addr){}
bool acl_is_member(const Key &PublicKey){}
///////////////////////////////////////////////////////
// mock of crypto code
///////////////////////////////////////////////////////

#include "crypto.h"

bool sha512_msg(const uint8_t *data, size_t data_size, sha512_data_t *out_hash)
{
    memset(out_hash, 7, sizeof(sha512_data_t));
    return true;
}

bool sha256_msg(const uint8_t *data, size_t data_size, sha256_data_t *out_hash)
{
    memset(out_hash, 7, sizeof(sha256_data_t));
    return true;
}

bool generate_aes_siv_key(const kdf32_key_t *ledger_kds, sha256_data_t public_key_hash, sha256_data_t transaction_nonce_hash, sha256_data_t address_hash, kdf32_key_t *aes_siv_key)
{
    memset(aes_siv_key, 7, sizeof(kdf32_key_t));
    return true;
}

bool aes_siv_encrypt(const uint8_t *in_buf, size_t in_buf_size,
                     const uint8_t *in_aad, size_t in_aad_size,
                     const uint8_t *aes_key, size_t aes_key_size,
                     uint8_t *out_buf, size_t out_buf_size)
{
    memcpy(out_buf, in_buf, out_buf_size);
    return true;
}

bool aes_siv_decrypt(const uint8_t *in_buf, size_t in_buf_size,
                     const uint8_t *in_aad, size_t in_aad_size,
                     const uint8_t *aes_key, size_t aes_key_size,
                     uint8_t *out_buf, size_t out_buf_size)
{
    memcpy(out_buf, in_buf, out_buf_size);
    return true;
}

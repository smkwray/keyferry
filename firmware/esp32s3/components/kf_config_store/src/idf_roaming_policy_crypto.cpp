#include "keyferry/idf_roaming_policy_crypto.h"

#include "psa/crypto.h"

namespace keyferry::config {
namespace {

void SecureClear(void* data, std::size_t length) {
  volatile auto* output = static_cast<volatile std::uint8_t*>(data);
  while (length-- != 0) {
    *output++ = 0;
  }
}

}  // namespace

bool IdfRoamingPolicyCrypto::Sha256(const std::uint8_t* input,
                                    const std::size_t length,
                                    std::uint8_t output[32]) {
  if (input == nullptr || length == 0 || output == nullptr) {
    return false;
  }
  std::size_t output_length = 0;
  const bool ok = psa_hash_compute(PSA_ALG_SHA_256, input, length, output, 32,
                                   &output_length) == PSA_SUCCESS &&
                  output_length == 32;
  if (!ok) {
    SecureClear(output, 32);
  }
  return ok;
}

bool IdfRoamingPolicyCrypto::HkdfSha256(
    const std::uint8_t* input_key, const std::size_t input_key_length,
    const std::uint8_t* salt, const std::size_t salt_length,
    const std::uint8_t* info, const std::size_t info_length,
    std::uint8_t output[32]) {
  if (input_key == nullptr || input_key_length == 0 || salt == nullptr ||
      salt_length == 0 || info == nullptr || info_length == 0 ||
      output == nullptr) {
    return false;
  }
  psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
  bool ok = psa_key_derivation_setup(
                &operation, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS &&
            psa_key_derivation_input_bytes(
                &operation, PSA_KEY_DERIVATION_INPUT_SALT, salt,
                salt_length) == PSA_SUCCESS &&
            psa_key_derivation_input_bytes(
                &operation, PSA_KEY_DERIVATION_INPUT_SECRET, input_key,
                input_key_length) == PSA_SUCCESS &&
            psa_key_derivation_input_bytes(
                &operation, PSA_KEY_DERIVATION_INPUT_INFO, info,
                info_length) == PSA_SUCCESS &&
            psa_key_derivation_output_bytes(&operation, output, 32) ==
                PSA_SUCCESS;
  if (psa_key_derivation_abort(&operation) != PSA_SUCCESS) {
    ok = false;
  }
  if (!ok) {
    SecureClear(output, 32);
  }
  return ok;
}

bool IdfRoamingPolicyCrypto::HmacSha256(
    const std::uint8_t key[32], const std::uint8_t* input,
    const std::size_t input_length, std::uint8_t output[32]) {
  if (key == nullptr || input == nullptr || input_length == 0 ||
      output == nullptr) {
    return false;
  }
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
  psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
  psa_set_key_bits(&attributes, 256);
  mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
  const bool imported =
      psa_import_key(&attributes, key, 32, &key_id) == PSA_SUCCESS;
  psa_reset_key_attributes(&attributes);
  std::size_t output_length = 0;
  bool ok = imported &&
            psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), input,
                            input_length, output, 32, &output_length) ==
                PSA_SUCCESS &&
            output_length == 32;
  if (MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key_id) != 0 &&
      psa_destroy_key(key_id) != PSA_SUCCESS) {
    ok = false;
  }
  if (!ok) {
    SecureClear(output, 32);
  }
  return ok;
}

}  // namespace keyferry::config

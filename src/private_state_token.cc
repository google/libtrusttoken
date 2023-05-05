/* Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#include <openssl/base64.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <private_state_token.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

#include <vector>

static std::vector<uint8_t> DecodeBase64(std::string in) {
  size_t len;
  if (!EVP_DecodedLength(&len, in.size())) {
    fprintf(stderr, "EVP_DecodedLength failed\n");
    return std::vector<uint8_t>();
  }

  std::vector<uint8_t> out;
  out.resize(len);
  if (!EVP_DecodeBase64(out.data(), &len, len, (const uint8_t *)in.data(),
                        in.size())) {
    fprintf(stderr, "EVP_DecodeBase64 failed\n");
    return std::vector<uint8_t>();
  }
  out.resize(len);
  return out;
}

static std::string EncodeBase64(const std::vector<uint8_t> in) {
  size_t len;
  if (!EVP_EncodedLength(&len, in.size())) {
    fprintf(stderr, "EVP_EncodedLength failed\n");
    return "";
  }
  std::vector<uint8_t> out;
  out.resize(len);
  if (!EVP_EncodeBlock(out.data(), in.data(), in.size())) {
    fprintf(stderr, "EVP_EncodeBlock failed\n");
    return "";
  }
  return std::string(out.begin(), out.end() - 1);
}

static const TRUST_TOKEN_METHOD *GetMethod(PrivateStateTokenVersion version) {
  switch (version) {
    case v1_allpublic:
      return TRUST_TOKEN_pst_v1_voprf();
  }
  fprintf(stderr, "Unknown Private State Token Version\n");
  return nullptr;
}

static std::string GetProtocolString(PrivateStateTokenVersion version) {
  switch (version) {
    case v1_allpublic:
      return "PrivateStateTokenV1VOPRF";
  }
  fprintf(stderr, "Unknown Private State Token Version\n");
  return "";
}

bool PrivateStateTokenIssuer::GenerateKey(PrivateStateTokenVersion version,
                                   std::vector<uint8_t> *out_public,
                                   std::vector<uint8_t> *out_private,
                                   uint32_t id) {
  const TRUST_TOKEN_METHOD *method = GetMethod(version);
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  if (!TRUST_TOKEN_generate_key(
          method, priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
          pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, id)) {
    fprintf(stderr, "TrustTokenGenerateKey failed\n");
    ERR_print_errors_fp(stderr);
    return false;
  }
  out_public->resize(pub_key_len);
  out_private->resize(priv_key_len);
  memcpy(out_public->data(), pub_key, pub_key_len);
  memcpy(out_private->data(), priv_key, priv_key_len);
  return true;
}

PrivateStateTokenIssuer::PrivateStateTokenIssuer(PrivateStateTokenVersion issuer_version,
                                   size_t max_batchsize) {
  version = issuer_version;
  const TRUST_TOKEN_METHOD *method = GetMethod(version);
  ctx = TRUST_TOKEN_ISSUER_new(method, max_batchsize);
  batchsize = max_batchsize;
}

PrivateStateTokenIssuer::~PrivateStateTokenIssuer() { TRUST_TOKEN_ISSUER_free(ctx); }

bool PrivateStateTokenIssuer::AddKey(std::vector<uint8_t> pub_key,
                              std::vector<uint8_t> priv_key, uint32_t id,
                              uint64_t expiry) {
  if (!TRUST_TOKEN_ISSUER_add_key(ctx, priv_key.data(), priv_key.size())) {
    fprintf(stderr, "PrivateStateTokenIssuer::AddKey failed\n");
    return false;
  }
  keys.push_back(std::make_tuple(pub_key, priv_key, id, expiry));
  return true;
}

std::string PrivateStateTokenIssuer::GetCommitment(int commitment_id) {
  std::ostringstream ss;
  ss << "{\"" << GetProtocolString(version) << "\": ";
  ss << "{\"protocol_version\": \"" << GetProtocolString(version) << "\", ";
  ss << "\"batchsize\": " << batchsize << ", ";
  ss << "\"keys\": {";
  bool firstKey = true;
  for (auto key : keys) {
    if (!firstKey) {
      ss << ", ";
    }
    firstKey = false;
    std::string pub_b64 = EncodeBase64(std::get<0>(key));
    ss << "\"" << std::get<2>(key) << "\": {\"Y\": \"" << pub_b64 << "\", ";
    ss << "\"expiry\": \"" << std::get<3>(key) << "\"}";
  }
  ss << "}";
  ss << ", ";
  ss << "\"id\": " << commitment_id << "}";
  ss << "}";
  return ss.str();
}

std::string PrivateStateTokenIssuer::Issue(size_t *out_tokens_issued,
                                    uint32_t public_metadata,
                                    size_t count,
                                    std::string request) {
  uint8_t *resp = NULL;
  size_t resp_len = 0;
  size_t tokens_issued;
  std::vector<uint8_t> input = DecodeBase64(request);
  if (!TRUST_TOKEN_ISSUER_issue(ctx, &resp, &resp_len, &tokens_issued,
                                input.data(), input.size(), public_metadata,
                                0, count)) {
    fprintf(stderr, "PrivateStateTokenIssuer::Issue failed\n");
    ERR_print_errors_fp(stderr);
    return "";
  }
  std::vector<uint8_t> response;
  response.resize(resp_len);
  memcpy(response.data(), resp, resp_len);
  OPENSSL_free(resp);
  *out_tokens_issued = tokens_issued;
  return EncodeBase64(response);
}

bool PrivateStateTokenIssuer::Redeem(uint32_t *out_public,
                              std::vector<uint8_t> *out_token,
                              std::string *out_client_data,
                              std::string request) {
  uint32_t public_metadata;
  uint8_t private_metadata;
  TRUST_TOKEN *rtoken;
  uint8_t *client_data;
  size_t client_data_len;
  std::vector<uint8_t> input = DecodeBase64(request);
  if (!TRUST_TOKEN_ISSUER_redeem_raw(ctx, &public_metadata, &private_metadata,
                                     &rtoken, &client_data, &client_data_len,
                                     input.data(), input.size())) {
    fprintf(stderr, "PrivateStateTokenIssuer::Redeem failed\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  *out_public = public_metadata;
  out_token->assign(rtoken->data, rtoken->data + rtoken->len);
  TRUST_TOKEN_free(rtoken);
  out_client_data->assign((char *)client_data, client_data_len);
  OPENSSL_free(client_data);
  return true;
}

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

#ifndef PRIVATE_STATE_TOKEN_H
#define PRIVATE_STATE_TOKEN_H

#include <openssl/base.h>
#include <openssl/trust_token.h>

#include <vector>


// PrivateStateTokenVersion represents what version of Private State Token to attempt with this
// issuer.
typedef enum private_state_token_version {
  v1_allpublic,
} PrivateStateTokenVersion;



class PrivateStateTokenIssuer {
public:
  PrivateStateTokenIssuer(PrivateStateTokenVersion issuer_version, size_t max_batchsize);
  ~PrivateStateTokenIssuer();

  // |GenerateKey| generates a new keypair for the Private State Token version |version|
  // with the ID |id|. It returns true on success and false on failure.
  static bool GenerateKey(PrivateStateTokenVersion version,
                          std::vector<uint8_t> *out_public,
                          std::vector<uint8_t> *out_private, uint32_t id);

  // Add a keypair |pub_key|, |priv_key| to the issuer with a specified |expiry|
  // for the key commitment and the indicated |id| (this should match the ID
  // used to generate the key. It returns true on success and false on failure.
  bool AddKey(std::vector<uint8_t> pub_key, std::vector<uint8_t> priv_key,
              uint32_t id, uint64_t expiry);

  // Returns the key commitment for this issuer with an ID of |commitment_id|.
  std::string GetCommitment(int commitment_id);

  // Attempts to issue up to |count| tokens requested in the Private State Token header |request|
  // using metadata values of |public_metadata| (one of the key IDs added to
  // this issuer). It returns the encoded response that should be included
  // in the Private State Token header.
  std::string Issue(size_t *out_tokens_issued, uint32_t public_metadata,
                    size_t count, std::string request);

  // Verifies the token provided in the Private State Token header |request| and outputs
  // the value of the metadata in |*out_public|, along with the raw token in |*out_token|
  // (which should be used to detect double-spending of the same token) and the client
  // data provided in the request in |*out_client_data|. The caller is responsible for
  // assembling a redemption record to return to the client. It returns true on success
  // and false on failure.
  bool Redeem(uint32_t *out_public, std::vector<uint8_t> *out_token,
              std::string *out_client_data, std::string request);

private:
  PrivateStateTokenVersion version;
  TRUST_TOKEN_ISSUER *ctx;
  size_t batchsize;
  std::vector<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, uint32_t,
                         uint64_t>>
      keys;
};

#endif  // PRIVATE_STATE_TOKEN_H

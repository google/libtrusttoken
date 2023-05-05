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

#include <sqlite3.h>

#include <openssl/base64.h>

#include <private_state_token.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

#include <vector>

#define BATCH_SIZE 1

using namespace std;

PrivateStateTokenVersion default_version = v1_allpublic;

bool RunQuery(sqlite3 *db, std::string query,
              int (*cb)(void *, int, char **, char **)) {
  char *error;
  int ret = sqlite3_exec(db, query.c_str(), cb, db, &error);
  if (ret != SQLITE_OK) {
    fprintf(stderr, "DB Error: %s\n", error);
    sqlite3_free(error);
    return false;
  }
  return true;
}

bool SetupTables(sqlite3 *db) {
  if (!RunQuery(db,
                "CREATE TABLE IF NOT EXISTS keys (id integer PRIMARY KEY, "
                "private BLOB, public BLOB);",
                NULL)) {
    return false;
  }
  if (!RunQuery(db,
                "CREATE TABLE IF NOT EXISTS tokens (id integer PRIMARY KEY, "
                "value BLOB);",
                NULL)) {
    return false;
  }
  return true;
}

bool AddKey(sqlite3 *db, int id) {
  std::vector<uint8_t> pub_key, priv_key;
  if (!PrivateStateTokenIssuer::GenerateKey(default_version, &pub_key, &priv_key, id))
    return false;

  sqlite3_stmt *stmt = NULL;
  int ret = sqlite3_prepare(
      db, "INSERT INTO keys(id, private, public) VALUES(?, ?, ?);",
      -1, &stmt, NULL);
  if (ret != SQLITE_OK || sqlite3_bind_int(stmt, 1, id) != SQLITE_OK ||
      sqlite3_bind_blob(stmt, 2, priv_key.data(), priv_key.size(),
                        SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_bind_blob(stmt, 3, pub_key.data(), pub_key.size(),
                        SQLITE_STATIC) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "DB Error: %s\n", sqlite3_errmsg(db));
    return false;
  }
  sqlite3_finalize(stmt);
  return true;
}

bool LoadKeys(sqlite3 *db, PrivateStateTokenIssuer *issuer) {
  sqlite3_stmt *stmt = NULL;
  int ret = sqlite3_prepare(db, "SELECT COUNT(*) from keys;",
                            -1, &stmt, NULL);
  if (ret != SQLITE_OK) {
    fprintf(stderr, "DB Error: %s\n", sqlite3_errmsg(db));
    return false;
  }
  sqlite3_step(stmt);
  int ttKeyCount = sqlite3_column_int(stmt, 0);
  sqlite3_finalize(stmt);
  while (ttKeyCount < 6) {
    if (!AddKey((sqlite3 *)db, ttKeyCount++)) {
      return false;
    }
  }

  ret = sqlite3_prepare(
      db, "SELECT id, private, public FROM keys;", -1, &stmt, 0);
  if (ret != SQLITE_OK) {
    fprintf(stderr, "DB Error: %s\n", sqlite3_errmsg(db));
    return false;
  }
  while (sqlite3_step(stmt) != SQLITE_DONE) {
    int id = sqlite3_column_int(stmt, 0);
    const uint8_t *priv = (const uint8_t *)sqlite3_column_blob(stmt, 1);
    size_t privLen = sqlite3_column_bytes(stmt, 1);
    const uint8_t *pub = (const uint8_t *)sqlite3_column_blob(stmt, 2);
    size_t pubLen = sqlite3_column_bytes(stmt, 2);
    std::vector<uint8_t> pub_vec;
    pub_vec.assign(pub, pub + pubLen);
    std::vector<uint8_t> priv_vec;
    priv_vec.assign(priv, priv + privLen);
    if (!issuer->AddKey(pub_vec, priv_vec, id, 1767139200000000)) {
      return false;
    }
  }

  return true;
}

bool CheckToken(sqlite3 *db, bool *out_found, std::vector<uint8_t> token) {
  sqlite3_stmt *stmt = NULL;
  int ret = sqlite3_prepare(db, "SELECT COUNT(*) from tokens WHERE value=?;",
                            -1, &stmt, NULL);
  if (ret != SQLITE_OK || sqlite3_bind_blob(stmt, 1, token.data(), token.size(),
                                            SQLITE_STATIC) != SQLITE_OK) {
    fprintf(stderr, "DB Error: %s\n", sqlite3_errmsg(db));
    return false;
  }
  sqlite3_step(stmt);
  int tokenCount = sqlite3_column_int(stmt, 0);
  sqlite3_finalize(stmt);
  if (tokenCount > 0) {
    *out_found = true;
    return true;
  }

  ret = sqlite3_prepare(db, "INSERT INTO tokens(value) VALUES(?);", -1, &stmt,
                        NULL);
  if (ret != SQLITE_OK ||
      sqlite3_bind_blob(stmt, 1, token.data(), token.size(), SQLITE_STATIC) !=
          SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "DB Error: %s\n", sqlite3_errmsg(db));
    return false;
  }
  sqlite3_finalize(stmt);
  *out_found = false;
  return true;
}

enum TTAction { KEYS, ISSUE, REDEEM, ECHO };

int main(int argc, char **argv, char **envp) {
  sqlite3 *db;
  if (sqlite3_open("/var/www/ttd.db", &db)) {
    fprintf(stderr, "DB Error: %s\n", sqlite3_errmsg(db));
    return 1;
  }

  if (!SetupTables(db)) {
    return 1;
  }

  PrivateStateTokenVersion version = v1_allpublic;
  const char *version_raw = std::getenv("HTTP_SEC_PRIVATE_STATE_TOKEN_CRYPTO_VERSION");
  if (version_raw != NULL) {
    string version_header = std::string(version_raw);
  }
  PrivateStateTokenIssuer *issuer = new PrivateStateTokenIssuer(version, BATCH_SIZE);
  if (!LoadKeys(db, issuer)) {
    return 1;
  }

  enum TTAction action = KEYS;

  const char *path_raw = std::getenv("REQUEST_URI");
  if (path_raw == NULL) {
    return 1;
  }
  string path = std::string(path_raw);


  if (path.find("/k") != std::string::npos) {
    action = KEYS;
  } else if (path.find("/i") != std::string::npos) {
    action = ISSUE;
  } else if (path.find("/r") != std::string::npos) {
    action = REDEEM;
  } else if (path.find("/echo") != std::string::npos) {
    action = ECHO;
  } else {
    cout << "\r\nBad Parameters.\r\n";
    return 1;
  }

  cout << "Content-type:text/plain\r\n";
  if (action == KEYS) {
    PrivateStateTokenIssuer *issuer = new PrivateStateTokenIssuer(v1_allpublic, BATCH_SIZE);
    if (!LoadKeys(db, issuer)) {
      return 1;
    }
    std::string commitment = issuer->GetCommitment(1);
    cout << "\r\n";
    cout << commitment << "\r\n";
  } else if (action == ISSUE) {
    const char *request = std::getenv("HTTP_SEC_PRIVATE_STATE_TOKEN");
    if (request == NULL) {
      cout << "\r\nSec-Private-State-Token header missing.\r\n";
      return 0;
    }

    uint32_t public_metadata = 0;

    const char *query_raw = std::getenv("QUERY_STRING");
    if (query_raw == NULL) {
      cout << "\r\nMissing query.\r\n";
      return 1;
    }
    std::string query = std::string(query_raw);

    size_t pos = 0;
    while (query.length()) {
      if ((pos = query.find("&")) == std::string::npos) {
        pos = query.length();
      }
      std::string param = query.substr(0, pos);
      size_t eqPos = param.find("=");
      if (eqPos != std::string::npos) {
        std::string key = param.substr(0, eqPos);
        std::string value = param.substr(eqPos + 1);
        try {
          if (key.compare("public") == 0) {
            public_metadata = std::stoi(value);
            if (public_metadata < 0 || public_metadata > 2) {
              cout << "\r\nBad Parameters.\r\n";
              return 1;
            }
          }
        } catch (...) {
          cout << "\r\nBad Parameters.\r\n";
          return 1;
        }
      }
      query.erase(0, pos + 1);
    }

    size_t tokens_issued;
    std::string resp = issuer->Issue(&tokens_issued, public_metadata,
                                     BATCH_SIZE, request);
    if (resp != "") {
      cout << "Sec-Private-State-Token: " << resp << "\r\n";
      cout << "Sec-PST-Count: Issuing " << tokens_issued << " tokens.\r\n";
      cout << "\r\n";
      cout << "Issuing " << tokens_issued << " tokens.\r\n";
    } else {
      cout << "\r\n\r\nError issuing tokens.\r\n";
    }
  } else if (action == REDEEM) {
    const char *request = std::getenv("HTTP_SEC_PRIVATE_STATE_TOKEN");
    if (request == NULL) {
      cout << "\r\nSec-Private-State-Token header missing.\r\n";
      return 0;
    }

    uint32_t public_metadata;
    std::vector<uint8_t> token;
    std::string client_data;
    if (!issuer->Redeem(&public_metadata, &token, &client_data, request)) {
      cout << "\r\nInternal error.\r\n";
      return 1;
    }

    // Make response.
    bool found = false;
    if (!CheckToken(db, &found, token)) {
      cout << "\r\nBad Private State Token.\r\n";
      return 1;
    }

    if (!found) {
      std::ostringstream ss;
      ss << "{\"public_metadata\": " << public_metadata << "}";
      std::string rr = ss.str();
      size_t len;
      if (!EVP_EncodedLength(&len, rr.size())) {
        cerr << "EVP_EncodedLength failed\n";
        cout << "\r\nInternal error.\r\n";
        return 1;
      }
      std::vector<uint8_t> out;
      out.resize(len);
      if (!EVP_EncodeBlock(out.data(), (const uint8_t*)rr.data(), rr.size())) {
        cerr << "EVP_EncodeBlock failed\n";
        cout << "\r\nInternal error.\r\n";
        return 1;
      }
      rr = std::string(out.begin(), out.end() - 1);

      cout << "Sec-Private-State-Token: " << rr << "\r\n";
      cout << "\r\n";

      cout << "Redeeming token.\r\n";
    } else {
      cout << "\r\n";

      cout << "Duplicate token.\r\n";
    }
  } else if (action == ECHO) {
    const char *rr = std::getenv("HTTP_SEC_REDEMPTION_RECORD");
    cout << "\r\n" << rr << "\r\n";
  }

  sqlite3_close(db);

  return 0;
}

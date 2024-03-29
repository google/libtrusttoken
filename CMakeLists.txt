# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.3)

include(ExternalProject)
include(deps.cmake)
project(libtrusttoken)

enable_language(CXX)

set(BORINGSSL_INSTALL_DIR ${CMAKE_BINARY_DIR}/boringssl)

ExternalProject_Add(boringssl
  GIT_REPOSITORY https://boringssl.googlesource.com/boringssl
  GIT_TAG ${BORINGSSL_HASH}
  CMAKE_ARGS -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release -DCMAKE_ASM_FLAGS=-Wa,--noexecstack
  INSTALL_COMMAND mkdir -p ${BORINGSSL_INSTALL_DIR} && cp -r ../boringssl/include/ ${BORINGSSL_INSTALL_DIR}/include && cp -r crypto ${BORINGSSL_INSTALL_DIR}
)

add_library(
  privatestatetoken

  src/private_state_token.cc
)

include_directories(${BORINGSSL_INSTALL_DIR}/include)
include_directories(include)
link_directories(${BORINGSSL_INSTALL_DIR}/crypto)

add_dependencies(privatestatetoken boringssl)
target_link_libraries(privatestatetoken crypto)

add_executable(
  tt_demo
  demo/tt_demo.cc
)
add_dependencies(tt_demo privatestatetoken boringssl)
target_link_libraries(tt_demo privatestatetoken pthread sqlite3)

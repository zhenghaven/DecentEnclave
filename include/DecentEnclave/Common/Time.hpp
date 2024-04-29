// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#ifdef DECENT_ENCLAVE_PLATFORM_SGX
#include "Sgx/Time.hpp"
#endif // DECENT_ENCLAVE_PLATFORM_SGX

namespace DecentEnclave
{
namespace Common
{

#ifdef DECENT_ENCLAVE_PLATFORM_SGX
using UntrustedTime = Sgx::UntrustedTime;
#endif // DECENT_ENCLAVE_PLATFORM_SGX

} // namespace Common
} // namespace DecentEnclave


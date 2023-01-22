// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <string>

#include <cppcodec/hex_lower.hpp>


#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
#include "Sgx/SealKey.hpp"

namespace DecentEnclave
{
namespace Trusted
{

using PlatformIdImpl = Sgx::PlatformId;

} // namespace Trusted
} // namespace DecentEnclave

#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED


namespace DecentEnclave
{
namespace Trusted
{

struct PlatformId : public PlatformIdImpl
{

static std::string GetIdHex()
{
	static const auto& id = GetId();
	static std::string idHex =
		cppcodec::hex_lower::encode(id.data(), id.size());

	return idHex;
}

}; // struct PlatformId

} // namespace Trusted
} // namespace DecentEnclave

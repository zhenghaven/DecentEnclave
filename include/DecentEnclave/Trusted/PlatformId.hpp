// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstdint>

#include <string>
#include <vector>

#include <SimpleObjects/Codec/Hex.hpp>

#include "../Common/Internal/SimpleObj.hpp"


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

	using Base = PlatformIdImpl;

	static std::vector<uint8_t> GetId()
	{
		auto id = Base::GetId();
		return std::vector<uint8_t>(id.begin(), id.end());
	}

	static std::string GetIdHex()
	{
		return Common::Internal::Obj::Codec::Hex::Encode<std::string>(
				GetId()
			);
	}

}; // struct PlatformId

} // namespace Trusted
} // namespace DecentEnclave

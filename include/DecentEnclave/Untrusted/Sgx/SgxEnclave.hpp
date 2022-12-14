// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once

#ifdef DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED

#include "../EnclaveBase.hpp"

#include <string>

#include <sgx_urts.h>
#include <sgx_edger8r.h>

#include <SimpleSysIO/SysCall/Files.hpp>

#include "../../Common/SimpleIO.hpp"
#include "../EnclaveExceptions.hpp"


namespace DecentEnclave
{
namespace Untrusted
{
namespace Sgx
{


class SgxEnclave : virtual public Untrusted::EnclaveBase
{
public:
	SgxEnclave(
		const std::string& enclaveImgPath = DECENT_ENCLAVE_PLATFORM_SGX_IMAGE,
		const std::string& launchTokenPath = DECENT_ENCLAVE_PLATFORM_SGX_TOKEN,
	) :
		m_encId(0)
	{
		sgx_launch_token_t token = { 0 };
		static constexpr size_t tokenLen = sizeof(sgx_launch_token_t);

		try
		{
			auto file = SysCall::RBinaryFile::Open(launchTokenPath);
			auto tokenBuf = file.ReadBytes<std::vector<uint8_t> >();
			if (tokenLen == tokenBuf.size())
			{
				std::copy(tokenBuf.begin(), tokenBuf.end(), std::begin(token));
			}
		}
		catch(const std::exception&)
		{
			// Failed to open token file, maybe it doesn't exist, which is fine
		}

		int updated = 0;
		sgx_status_t ret = sgx_create_enclave(
			enclaveImgPath.c_str(),
			SGX_DEBUG_FLAG,
			&token,
			&updated,
			&m_encId,
			nullptr
		);

		if (ret != SGX_SUCCESS)
		{
			// TODO: use sgx exception containing status code
			throw EnclaveException("Failed to launch enclave");
		}

		if (updated == 1)
		{
			std::vector<uint8_t> tokenBuf(std::begin(token), std::end(token));

			auto file = SysCall::WBinaryFile::Create(launchTokenPath);
			file.WriteBytes(tokenBuf);
		}
	}

	SgxEnclave(const SgxEnclave& other) = delete;
	SgxEnclave(SgxEnclave&& other) = delete;

	// LCOV_EXCL_START
	virtual ~SgxEnclave()
	{
		sgx_destroy_enclave(m_encId);
	}
	// LCOV_EXCL_STOP

	SgxEnclave& operator=(const SgxEnclave& other) = delete;
	SgxEnclave& operator=(SgxEnclave&& other) = delete;

private:

	sgx_enclave_id_t m_encId;
}; // class SgxEnclave


} // namespace Sgx
} // namespace Untrusted
} // namespace DecentEnclave

#endif // DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED

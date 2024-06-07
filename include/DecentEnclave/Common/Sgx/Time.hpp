// Copyright (c) 2024 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#ifdef DECENT_ENCLAVE_PLATFORM_SGX
#include <cstdint>

#include "Exceptions.hpp"
#if defined(DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED)
#include "../../SgxEdgeSources/sys_io_t.h"
#elif defined(DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED)
#include "../../SgxEdgeSources/sys_io_u.h"
#endif // defined(DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED)


namespace DecentEnclave
{
namespace Common
{
namespace Sgx
{


struct UntrustedTime
{

	static uint64_t Timestamp()
	{
		return MakeOCall(ocall_decent_untrusted_timestamp);
	}

	static uint64_t TimestampMillSec()
	{
		return MakeOCall(ocall_decent_untrusted_timestamp_ms);
	}

	static uint64_t TimestampMicrSec()
	{
		return MakeOCall(ocall_decent_untrusted_timestamp_us);
	}

	static uint64_t TimestampNanoSec()
	{
		return MakeOCall(ocall_decent_untrusted_timestamp_ns);
	}

private:

#if defined(DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED)
	typedef sgx_status_t (*OCallFunc)(uint64_t*);
#elif defined(DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED)
	typedef uint64_t (*OCallFunc)();
#endif // defined(DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED)

	static uint64_t MakeOCall(OCallFunc UntrustedTimestampFunc)
	{
		uint64_t ret = 0;
#if defined(DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED)
		DECENTENCLAVE_SGX_OCALL_CHECK_ERROR_E(
			UntrustedTimestampFunc,
			&ret
		);
#elif defined(DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED)
		ret = UntrustedTimestampFunc();
#endif // defined(DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED)
		return ret;
	}

}; // struct UntrustedTime


} // namespace Sgx
} // namespace Common
} // namespace DecentEnclave

#endif // DECENT_ENCLAVE_PLATFORM_SGX


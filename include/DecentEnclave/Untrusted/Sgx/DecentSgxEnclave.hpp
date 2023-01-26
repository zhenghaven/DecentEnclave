// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#ifdef DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED

#include <vector>

#include "../DecentEnclaveBase.hpp"
#include "SgxEnclave.hpp"


extern "C" sgx_status_t ecall_decent_common_init(
	sgx_enclave_id_t eid,
	sgx_status_t* retval,
	const uint8_t* auth_list,
	size_t auth_list_size
);


namespace DecentEnclave
{
namespace Untrusted
{
namespace Sgx
{


class DecentSgxEnclave :
	public SgxEnclave,
	virtual public DecentEnclaveBase

{
public: // static members:
	using EncBase = DecentEnclaveBase;
	using SgxBase = SgxEnclave;

public:

	DecentSgxEnclave(
		const std::vector<uint8_t>& authList,
		const std::string& enclaveImgPath = DECENT_ENCLAVE_PLATFORM_SGX_IMAGE,
		const std::string& launchTokenPath = DECENT_ENCLAVE_PLATFORM_SGX_TOKEN
	) :
		SgxBase(enclaveImgPath, launchTokenPath)
	{
		sgx_status_t funcRet = SGX_ERROR_UNEXPECTED;
		sgx_status_t edgeRet = ecall_decent_common_init(
			m_encId,
			&funcRet,
			authList.data(),
			authList.size()
		);
		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			edgeRet,
			ecall_decent_common_init
		);
		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			funcRet,
			ecall_decent_common_init
		);
	}

	// LCOV_EXCL_START
	virtual ~DecentSgxEnclave() = default;
	// LCOV_EXCL_STOP

#ifdef _MSC_VER
// mitigating MSVC compiler bug:
// https://stackoverflow.com/questions/469508/visual-studio-compiler-warning-c4250-class1-inherits-class2member-via-d
// https://stackoverflow.com/questions/6864550/c-inheritance-via-dominance-warning
	virtual const char* GetPlatformName() const override
	{
		return SgxBase::GetPlatformName();
	}
#else // _MSC_VER
	using SgxBase::GetPlatformName;
#endif // _MSC_VER

}; // class DecentSgxEnclave


} // namespace Sgx
} // namespace Untrusted
} // namespace DecentEnclave

#endif // DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED

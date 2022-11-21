// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#ifdef DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED


#include "../DecentEnclaveBase.hpp"
#include "SgxEnclave.hpp"


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

	using SgxBase::SgxBase;

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

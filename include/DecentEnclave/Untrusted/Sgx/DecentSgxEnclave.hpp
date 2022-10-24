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

}; // class DecentSgxEnclave


} // namespace Sgx
} // namespace Untrusted
} // namespace DecentEnclave

#endif // DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED


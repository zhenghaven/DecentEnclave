// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <memory>

#include <sgx_error.h>
#include <SimpleObjects/Internal/make_unique.hpp>

#include "../Common/Internal/SimpleSysIO.hpp"
#include "../Common/Internal/SimpleObj.hpp"
#include "../Common/Platform/Print.hpp"
#include "../Trusted/Sgx/ComponentConnection.hpp"


extern "C" sgx_status_t ecall_decent_lambda_handler(
	void* sock_ptr
)
{
	using namespace DecentEnclave::Common;
	using namespace DecentEnclave::Common::Internal;
	using namespace DecentEnclave::Trusted::Sgx;
	using namespace DecentEnclave::Common::Internal::SysIO;

	StreamSocketBase* realSockPtr = static_cast<StreamSocketBase*>(sock_ptr);

	std::unique_ptr<StreamSocket> sock =
		Obj::Internal::make_unique<StreamSocket>(realSockPtr);

	Platform::Print::StrDebug("Decent App lambda handler; work in progress...");

	return SGX_SUCCESS;
}

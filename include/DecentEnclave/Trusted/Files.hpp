// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <string>

#include <SimpleObjects/Internal/make_unique.hpp>
#include <SimpleSysIO/BinaryIOStreamBase.hpp>


#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
#include "Sgx/Files.hpp"

namespace DecentEnclave
{
namespace Trusted
{

using UntrustedFileImpl = Sgx::UntrustedFileImpl;

} // namespace Trusted
} // namespace DecentEnclave

#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED


namespace DecentEnclave
{
namespace Trusted
{


template<
	template<typename> class _WrapperType,
	typename _BaseType
>
struct UntrustedFileOpenerImpl
{

	using ImplType = UntrustedFileImpl;
	using WrapperType = _WrapperType<ImplType>;
	using RetType = std::unique_ptr<_BaseType>;

protected:

	static RetType OpenImpl(
		const std::string& path,
		const std::string& mode
	)
	{
		auto impl =
			SimpleObjects::Internal::make_unique<ImplType>(path, mode);

		return
			SimpleObjects::Internal::make_unique<WrapperType>(
				std::move(impl)
			);
	}

}; // struct UntrustedFileOpenerImpl

struct RBUntrustedFile :
	UntrustedFileOpenerImpl<
		SimpleSysIO::RBinaryIOSWrapper,
		SimpleSysIO::RBinaryIOSBase
	>
{
	static RetType Open(const std::string& path)
	{
		return OpenImpl(path, "rb");
	}
}; // struct RBinaryFile


struct WBUntrustedFile :
	UntrustedFileOpenerImpl<
		SimpleSysIO::WBinaryIOSWrapper,
		SimpleSysIO::WBinaryIOSBase
	>
{
	static RetType Create(const std::string& path)
	{
		return OpenImpl(path, "wb");
	}

	static RetType Append(const std::string& path)
	{
		return OpenImpl(path, "ab");
	}
}; // struct WBinaryFile


struct RWBUntrustedFile :
	UntrustedFileOpenerImpl<
		SimpleSysIO::RWBinaryIOSWrapper,
		SimpleSysIO::RWBinaryIOSBase
	>
{
	static RetType Create(const std::string& path)
	{
		return OpenImpl(path, "wb+");
	}

	static RetType Append(const std::string& path)
	{
		return OpenImpl(path, "ab+");
	}
}; // struct RWBinaryFile


} // namespace Trusted
} // namespace DecentEnclave

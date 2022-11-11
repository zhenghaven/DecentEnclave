// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <cstdio>
#include <cstdint>

#include "../Common/Platform/Print.hpp"
#include "../Common/Sgx/UntrustedBuffer.hpp"


extern "C" void ocall_decent_enclave_print_str(const char* str)
{
	std::printf("%s", str);
}

extern "C" void ocall_decent_untrusted_buffer_delete(
	uint8_t data_type,
	void* ptr
)
{
	DecentEnclave::Common::Sgx::UBufferDataType dataType =
		static_cast<DecentEnclave::Common::Sgx::UBufferDataType>(data_type);

	switch (dataType)
	{
	case DecentEnclave::Common::Sgx::UBufferDataType::Bytes:
		delete[] static_cast<uint8_t*>(ptr);
		break;
	case DecentEnclave::Common::Sgx::UBufferDataType::String:
		delete[] static_cast<char*>(ptr);
		break;
	default:
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_untrusted_buffer_delete received unknown type - " +
			std::to_string(static_cast<int>(data_type))
		);
		break;
	}
}

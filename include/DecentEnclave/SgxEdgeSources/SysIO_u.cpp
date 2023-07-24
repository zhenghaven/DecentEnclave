// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <cstdio>
#include <cstdint>
#include <ctime>

#include <sgx_error.h>
#include <SimpleObjects/Internal/make_unique.hpp>
#include <SimpleSysIO/SysCall/Files.hpp>

#include "../Common/Internal/SimpleObj.hpp"
#include "../Common/Internal/SimpleSysIO.hpp"
#include "../Common/Platform/Print.hpp"
#include "../Common/Sgx/Exceptions.hpp"
#include "../Common/Sgx/UntrustedBuffer.hpp"
#include "../Untrusted/Config/EndpointsMgr.hpp"
#include "sys_io_u.h"


extern "C" void ocall_decent_enclave_print_str(const char* str)
{
	DecentEnclave::Common::Platform::Print::Str(str);
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

extern "C" uint64_t ocall_decent_untrusted_timestamp()
{
	return static_cast<uint64_t>(std::time(nullptr));
}


// ====================
// Untrusted File
// ====================

extern "C" sgx_status_t ocall_decent_untrusted_file_open(
	void** ptr,
	const char* path,
	const char* mode
)
{
	using namespace DecentEnclave::Common::Internal::SysIO::
		SysCall::SysCallInternal;
	using namespace DecentEnclave::Common::Internal::Obj::Internal;
	try
	{
		auto inst = make_unique<COpenImpl>(path, mode);
		*ptr = inst.release();
		return SGX_SUCCESS;
	}
	catch(const std::exception& e)
	{
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_untrusted_file_open failed to open file with error " +
			std::string(e.what())
		);
		return SGX_ERROR_UNEXPECTED;
	}
}

extern "C" void ocall_decent_untrusted_file_close(
	void* ptr
)
{
	using namespace DecentEnclave::Common::Internal::SysIO::
		SysCall::SysCallInternal;
	COpenImpl* realPtr = static_cast<COpenImpl*>(ptr);

	delete realPtr;
}

extern "C" sgx_status_t ocall_decent_untrusted_file_seek(
	void* ptr,
	ptrdiff_t offset,
	uint8_t whence
)
{
	using namespace DecentEnclave::Common::Internal::SysIO;
	using namespace DecentEnclave::Common::Internal::SysIO::
		SysCall::SysCallInternal;
	COpenImpl* realPtr = static_cast<COpenImpl*>(ptr);

	try
	{
		realPtr->Seek(offset, static_cast<SeekWhence>(whence));
		return SGX_SUCCESS;
	}
	catch (const std::exception& e)
	{
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_untrusted_file_seek failed with error " +
			std::string(e.what())
		);
		return SGX_ERROR_UNEXPECTED;
	}
}

extern "C" sgx_status_t ocall_decent_untrusted_file_tell(
	const void* ptr,
	size_t* out_val
)
{
	using namespace DecentEnclave::Common::Internal::SysIO::
		SysCall::SysCallInternal;
	const COpenImpl* realPtr = static_cast<const COpenImpl*>(ptr);

	try
	{
		*out_val = realPtr->Tell();
		return SGX_SUCCESS;
	}
	catch (const std::exception& e)
	{
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_untrusted_file_tell failed with error " +
			std::string(e.what())
		);
		return SGX_ERROR_UNEXPECTED;
	}
}

extern "C" sgx_status_t ocall_decent_untrusted_file_flush(
	void* ptr
)
{
	using namespace DecentEnclave::Common::Internal::SysIO::
		SysCall::SysCallInternal;
	COpenImpl* realPtr = static_cast<COpenImpl*>(ptr);

	try
	{
		realPtr->Flush();
		return SGX_SUCCESS;
	}
	catch (const std::exception& e)
	{
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_untrusted_file_flush failed with error " +
			std::string(e.what())
		);
		return SGX_ERROR_UNEXPECTED;
	}
}

extern "C" sgx_status_t ocall_decent_untrusted_file_read(
	void* ptr,
	size_t size,
	uint8_t** out_buf,
	size_t* out_buf_size
)
{
	using namespace DecentEnclave::Common::Internal::SysIO::
		SysCall::SysCallInternal;
	COpenImpl* realPtr = static_cast<COpenImpl*>(ptr);

	try
	{
		*out_buf = new uint8_t[size];
		*out_buf_size = realPtr->ReadBytesRaw(*out_buf, size);
		return SGX_SUCCESS;
	}
	catch (const std::exception& e)
	{
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_untrusted_file_read failed with error " +
			std::string(e.what())
		);
		return SGX_ERROR_UNEXPECTED;
	}
}

extern "C" sgx_status_t ocall_decent_untrusted_file_write(
	void* ptr,
	const uint8_t* in_buf,
	size_t in_buf_size,
	size_t* out_size
)
{
	using namespace DecentEnclave::Common::Internal::SysIO::
		SysCall::SysCallInternal;
	COpenImpl* realPtr = static_cast<COpenImpl*>(ptr);

	try
	{
		*out_size = realPtr->WriteBytesRaw(in_buf, in_buf_size);
		return SGX_SUCCESS;
	}
	catch (const std::exception& e)
	{
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_untrusted_file_write failed with error " +
			std::string(e.what())
		);
		return SGX_ERROR_UNEXPECTED;
	}
}


// ====================
// Networking
// ====================


extern "C" sgx_status_t ocall_decent_endpoint_connect(
	void** ptr,
	const char* name
)
{
	using namespace DecentEnclave::Untrusted;
	try
	{
		auto inst = Config::EndpointsMgr::GetInstance().GetStreamSocket(name);
		*ptr = inst.release();
		return SGX_SUCCESS;
	}
	catch(const std::exception& e)
	{
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_endpoint_connect failed with error " +
			std::string(e.what())
		);
		return SGX_ERROR_UNEXPECTED;
	}
}

extern "C" void ocall_decent_ssocket_disconnect(
	void* ptr
)
{
	using namespace DecentEnclave::Untrusted;
	using _SSocketType = Config::EndpointsMgr::StreamSocketType;
	std::unique_ptr<_SSocketType> realPtr(static_cast<_SSocketType*>(ptr));
}

extern "C" sgx_status_t ocall_decent_ssocket_send_raw(
	void* ptr,
	const uint8_t* in_buf,
	size_t in_buf_size,
	size_t* out_size
)
{
	using namespace DecentEnclave::Untrusted;
	using namespace DecentEnclave::Common::Internal::SysIO;
	using _SSocketType = Config::EndpointsMgr::StreamSocketType;
	_SSocketType* realPtr = static_cast<_SSocketType*>(ptr);

	try
	{
		*out_size = StreamSocketRaw::Send(*realPtr, in_buf, in_buf_size);
		return SGX_SUCCESS;
	}
	catch (const std::exception& e)
	{
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_ssocket_send_raw failed with error " +
			std::string(e.what())
		);
		return SGX_ERROR_UNEXPECTED;
	}
}

extern "C" sgx_status_t ocall_decent_ssocket_recv_raw(
	void* ptr,
	size_t size,
	uint8_t** out_buf,
	size_t* out_buf_size
)
{
	using namespace DecentEnclave::Untrusted;
	using namespace DecentEnclave::Common::Internal::SysIO;
	using _SSocketType = Config::EndpointsMgr::StreamSocketType;
	_SSocketType* realPtr = static_cast<_SSocketType*>(ptr);

	try
	{
		*out_buf = new uint8_t[size];
		*out_buf_size = StreamSocketRaw::Recv(*realPtr, *out_buf, size);
		return SGX_SUCCESS;
	}
	catch (const std::exception& e)
	{
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_ssocket_recv_raw failed with error " +
			std::string(e.what())
		);
		return SGX_ERROR_UNEXPECTED;
	}
}


static
inline
typename DecentEnclave::Common::Internal::
	SysIO::StreamSocketBase::AsyncRecvCallback
MakeAsyncRecvCallback(
	sgx_enclave_id_t enclave_id,
	uint64_t handler_reg_id
)
{
	return [
				enclave_id,
				handler_reg_id
			](std::vector<uint8_t> recvData, bool hasErrorOccurred) -> void
		{
			DECENTENCLAVE_SGX_ECALL_CHECK_ERROR_E_R(
				ecall_decent_ssocket_async_recv_raw_callback,
				enclave_id,
				handler_reg_id,
				recvData.data(),
				recvData.size(),
				hasErrorOccurred ? 1 : 0
			);
		};
}


extern "C" sgx_status_t ocall_decent_ssocket_async_recv_raw(
	void* ptr,
	size_t size,
	sgx_enclave_id_t enclave_id,
	uint64_t handler_reg_id
)
{
	using namespace DecentEnclave::Untrusted;
	using namespace DecentEnclave::Common::Internal::SysIO;
	using _SSocketType = Config::EndpointsMgr::StreamSocketType;
	_SSocketType* realPtr = static_cast<_SSocketType*>(ptr);

	try
	{
		StreamSocketRaw::AsyncRecv(
			*realPtr,
			size,
			MakeAsyncRecvCallback(enclave_id, handler_reg_id)
		);
		return SGX_SUCCESS;
	}
	catch (const std::exception& e)
	{
		DecentEnclave::Common::Platform::Print::StrDebug(
			"ocall_decent_ssocket_async_recv_raw failed with error " +
			std::string(e.what())
		);
		return SGX_ERROR_UNEXPECTED;
	}
}

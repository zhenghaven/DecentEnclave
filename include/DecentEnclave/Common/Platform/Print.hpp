// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <string>

#include "../Exceptions.hpp"

#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
#include "../../SgxEdgeSources/sys_io_t.h"
#else
#include <cstdio>
#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED


namespace DecentEnclave
{
namespace Common
{
namespace Platform
{

struct Print
{

	static void Str(const std::string& str)
	{
#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
		auto res = ocall_decent_enclave_print_str(str.c_str());
		if (res != SGX_SUCCESS)
		{
			// TODO: use SGX specific exception
			throw Exception("Failed to print string in SGX enclave.");
		}
#else
		std::printf("%s", str.c_str());
#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
	}

	static void StrDebug(const std::string& str)
	{
#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
		Str("DEBUG(T): " + str + "\n");
#else
		Str("DEBUG(U): " + str + "\n");
#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
	}

	static void StrInfo(const std::string& str)
	{
#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
		Str("INFO(T): " + str + "\n");
#else
		Str("INFO(U): " + str + "\n");
#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
	}

	static void StrErr(const std::string& str)
	{
#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
		Str("ERROR(T): " + str + "\n");
#else
		Str("ERROR(U): " + str + "\n");
#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
	}

}; // struct Print


} // namespace Platform
} // namespace Common
} // namespace DecentEnclave

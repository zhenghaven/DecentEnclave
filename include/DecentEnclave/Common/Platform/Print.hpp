// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstdint>

#include <string>

#include <SimpleObjects/ToString.hpp>

#include "../Exceptions.hpp"
#include "../Internal/SimpleObj.hpp"

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
		Str(AsmLineLeader(GetDebugLabel(), GetPlatformSymbol()) + str + "\n");
	}

	static void StrInfo(const std::string& str)
	{
		Str(AsmLineLeader(GetInfoLabel(), GetPlatformSymbol()) + str + "\n");
	}

	static void StrErr(const std::string& str)
	{
		Str(AsmLineLeader(GetErrLabel(), GetPlatformSymbol()) + str + "\n");
	}

	static void Hex(const void* data, const size_t size)
	{
		std::string res;
		Common::Internal::Obj::Internal::BytesToHEX<false, char>(
			std::back_inserter(res),
			static_cast<const uint8_t*>(data),
			static_cast<const uint8_t*>(data) + size
		);
		Str(res);
	}

	static void HexDebug(const void* data, const size_t size)
	{
		std::string res;
		Common::Internal::Obj::Internal::BytesToHEX<false, char>(
			std::back_inserter(res),
			static_cast<const uint8_t*>(data),
			static_cast<const uint8_t*>(data) + size
		);
		StrDebug(res);
	}

	static void Ptr(const void* ptr)
	{
		Str(Ptr2Str(ptr));
	}

	static void HexDebug(const void* ptr)
	{
		StrDebug(Ptr2Str(ptr));
	}

	static void MemDebug(const void* data, const size_t size)
	{
		StrDebug(
			"Memory dump @ " + Ptr2Str(data) +
			", size: " + std::to_string(size) + ":"
		);
		HexDebug(data, size);
		StrDebug("\n");
	}


	// Helper functions:

	static std::string GetPlatformSymbol()
	{
#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
		return "SGX-T";
#else
		return "APP-U";
#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
	}

	static std::string GetInfoLabel()
	{
		return "INFO";
	}

	static std::string GetDebugLabel()
	{
		return "DEBUG";
	}

	static std::string GetErrLabel()
	{
		return "ERROR";
	}

	static std::string AsmLineLeader(
		const std::string& label,
		const std::string& platSym
	)
	{
		return label + "(" + platSym + ")" + ": ";
	}

	static std::string Ptr2Str(
		const void* ptr
	)
	{
		auto val = reinterpret_cast<std::uintptr_t>(ptr);

		std::string res;
		Common::Internal::Obj::Internal::PrimitiveToHEX<true, char>(
			std::back_inserter(res),
			val
		);

		return res;
	}

}; // struct Print


} // namespace Platform
} // namespace Common
} // namespace DecentEnclave

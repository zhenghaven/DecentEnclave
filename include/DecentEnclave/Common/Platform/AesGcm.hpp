// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <array>
#include <utility>
#include <vector>

#include <mbedTLScpp/Container.hpp>
#include <mbedTLScpp/SecretVector.hpp>

#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
#include <sgx_tcrypto.h>
#include "../Sgx/Exceptions.hpp"
#else
#include <mbedTLScpp/Gcm.hpp>
#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED


namespace DecentEnclave
{
namespace Common
{
namespace Platform
{


#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED

class AesGcm128OneGoNative
{
public:

	AesGcm128OneGoNative() = default;

	~AesGcm128OneGoNative() = default;

	template<
		typename _KeyCtnType,
		typename _IvCtnType,   bool _IvCtnSecrecy,
		typename _AadCtnType,  bool _AadCtnSecrecy,
		typename _DataCtnType, bool _DataCtnSecrecy
	>
	std::pair<
		std::vector<uint8_t>,
		std::array<uint8_t, 16>
	>
	Encrypt(
		const mbedTLScpp::ContCtnReadOnlyRef<_KeyCtnType,  true>& key,
		const mbedTLScpp::ContCtnReadOnlyRef<_IvCtnType,   _IvCtnSecrecy>& iv,
		const mbedTLScpp::ContCtnReadOnlyRef<_AadCtnType,  _AadCtnSecrecy>& aad,
		const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataCtnSecrecy>& data
	)
	{
		std::vector<uint8_t> res(data.GetRegionSize());
		std::array<uint8_t, 16> tag;

		const sgx_aes_gcm_128bit_key_t* keyPtr =
			reinterpret_cast<const sgx_aes_gcm_128bit_key_t*>(key.BeginBytePtr());
		sgx_aes_gcm_128bit_tag_t* tagPtr =
			reinterpret_cast<sgx_aes_gcm_128bit_tag_t*>(tag.data());

		sgx_status_t sgxRet = sgx_rijndael128GCM_encrypt(
			keyPtr,
			data.BeginBytePtr(),
			static_cast<uint32_t>(data.GetRegionSize()),
			res.data(),
			iv.BeginBytePtr(),
			static_cast<uint32_t>(iv.GetRegionSize()),
			aad.BeginBytePtr(),
			static_cast<uint32_t>(aad.GetRegionSize()),
			tagPtr
		);
		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			sgx_rijndael128GCM_encrypt
		);

		return std::make_pair(std::move(res), std::move(tag));
	}

	template<
		typename _KeyCtnType,
		typename _IvCtnType,   bool _IvCtnSecrecy,
		typename _AadCtnType,  bool _AadCtnSecrecy,
		typename _DataCtnType, bool _DataCtnSecrecy,
		typename _TagCtnType,  bool _TagCtnSecrecy
	>
	mbedTLScpp::SecretVector<uint8_t>
	Decrypt(
		const mbedTLScpp::ContCtnReadOnlyRef<_KeyCtnType,  true>& key,
		const mbedTLScpp::ContCtnReadOnlyRef<_IvCtnType,   _IvCtnSecrecy>& iv,
		const mbedTLScpp::ContCtnReadOnlyRef<_AadCtnType,  _AadCtnSecrecy>& aad,
		const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataCtnSecrecy>& data,
		const mbedTLScpp::ContCtnReadOnlyRef<_TagCtnType, _TagCtnSecrecy>& tag
	)
	{
		mbedTLScpp::SecretVector<uint8_t> res(data.GetRegionSize());

		const sgx_aes_gcm_128bit_key_t* keyPtr =
			reinterpret_cast<const sgx_aes_gcm_128bit_key_t*>(key.BeginBytePtr());
		const sgx_aes_gcm_128bit_tag_t* tagPtr =
			reinterpret_cast<const sgx_aes_gcm_128bit_tag_t*>(tag.BeginBytePtr());

		sgx_status_t sgxRet = sgx_rijndael128GCM_decrypt(
			keyPtr,
			data.BeginBytePtr(),
			static_cast<uint32_t>(data.GetRegionSize()),
			res.data(),
			iv.BeginBytePtr(),
			static_cast<uint32_t>(iv.GetRegionSize()),
			aad.BeginBytePtr(),
			static_cast<uint32_t>(aad.GetRegionSize()),
			tagPtr
		);
		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			sgx_rijndael128GCM_decrypt
		);

		return res;
	}

}; // class AesGcm128OneGoNative

#else //#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED

class AesGcm128OneGoNative
{
public:

	AesGcm128OneGoNative() = default;

	~AesGcm128OneGoNative() = default;

	template<
		typename _KeyCtnType,
		typename _IvCtnType,   bool _IvCtnSecrecy,
		typename _AadCtnType,  bool _AadCtnSecrecy,
		typename _DataCtnType, bool _DataCtnSecrecy
	>
	std::pair<
		std::vector<uint8_t>,
		std::array<uint8_t, 16>
	>
	Encrypt(
		const mbedTLScpp::ContCtnReadOnlyRef<_KeyCtnType,  true>& key,
		const mbedTLScpp::ContCtnReadOnlyRef<_IvCtnType,   _IvCtnSecrecy>& iv,
		const mbedTLScpp::ContCtnReadOnlyRef<_AadCtnType,  _AadCtnSecrecy>& aad,
		const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataCtnSecrecy>& data
	)
	{
		mbedTLScpp::Gcm<mbedTLScpp::CipherType::AES, 128> gcm(
			mbedTLScpp::CtnFullR(key)
		);

		return gcm.Encrypt(
			data,
			iv,
			aad
		);
	}

	template<
		typename _KeyCtnType,
		typename _IvCtnType,   bool _IvCtnSecrecy,
		typename _AadCtnType,  bool _AadCtnSecrecy,
		typename _DataCtnType, bool _DataCtnSecrecy,
		typename _TagCtnType,  bool _TagCtnSecrecy
	>
	mbedTLScpp::SecretVector<uint8_t>
	Decrypt(
		const mbedTLScpp::ContCtnReadOnlyRef<_KeyCtnType,  true>& key,
		const mbedTLScpp::ContCtnReadOnlyRef<_IvCtnType,   _IvCtnSecrecy>& iv,
		const mbedTLScpp::ContCtnReadOnlyRef<_AadCtnType,  _AadCtnSecrecy>& aad,
		const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataCtnSecrecy>& data,
		const mbedTLScpp::ContCtnReadOnlyRef<_TagCtnType, _TagCtnSecrecy>& tag
	)
	{
		mbedTLScpp::Gcm<mbedTLScpp::CipherType::AES, 128> gcm(
			mbedTLScpp::CtnFullR(key)
		);

		return gcm.Decrypt(
			data,
			iv,
			aad,
			tag
		);
	}

}; // class AesGcm128OneGoNative

#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED


} // namespace Platform
} // namespace Common
} // namespace DecentEnclave

// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstdint>

#include <array>
#include <vector>

#include <cppcodec/hex_lower.hpp>
#include <mbedTLScpp/Hash.hpp>
#include <mbedTLScpp/PKey.hpp>


namespace DecentEnclave
{
namespace Common
{

class Keyring;


class KeyringKey
{
public: // static members:


	using PKeyType = mbedTLScpp::PKeyBase<>;


public:

	KeyringKey() = default;

	virtual ~KeyringKey() = default;


	//==========
	// Abstract methods
	//==========


	virtual const PKeyType& GetPkey() const = 0;


	virtual const std::string& GetName() const = 0;


	//==========
	// Helper methods
	//==========


	std::vector<uint8_t> GetPublicDer() const
	{
		return GetPkey().GetPublicDer();
	}


	std::array<uint8_t, 32UL> GetKeySha256() const
	{
		using _Hasher = mbedTLScpp::Hasher<mbedTLScpp::HashType::SHA256>;

		auto der = GetPublicDer();
		auto hash = _Hasher().Calc(
			mbedTLScpp::CtnFullR(der)
		);

		return hash.m_data;
	}


	std::string GetKeySha256Hex() const
	{
		std::string hex = cppcodec::hex_lower::encode(GetKeySha256());
		return hex;
	}


	bool IsRegistered(const Keyring& kr) const;


protected:


	void CheckRegistration(const Keyring& kr) const
	{
		static const bool sk_isRegistered = IsRegistered(kr);
		if (!sk_isRegistered)
		{
			throw Exception(
				"KeyringKey must be registered to a Keyring before use"
			);
		}
	}


}; // class KeyringKey


} // namespace Common
} // namespace DecentEnclave

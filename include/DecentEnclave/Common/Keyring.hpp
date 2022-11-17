// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <type_traits>
#include <unordered_map>

#include <SimpleObjects/SimpleObjects.hpp>

#include "Exceptions.hpp"
#include "KeyringKey.hpp"


namespace DecentEnclave
{
namespace Common
{


class Keyring
{
public: // static members:

	using KeyReference = std::reference_wrapper<const KeyringKey>;
	using PKeyType = typename KeyringKey::PKeyType;


	/**
	 * @brief Get the Instance object.
	 *        There can only be one instance of Keyring
	 *
	 * @return Keyring&
	 */
	static Keyring& GetMutableInstance()
	{
		static Keyring s_inst;
		return s_inst;
	}


	static const Keyring& GetInstance()
	{
		return GetMutableInstance();
	}


public:


	virtual ~Keyring() = default;


	const PKeyType& operator[](const std::string& keyName) const
	{
		auto it = m_keyNameMap.find(keyName);
		if (it == m_keyNameMap.end())
		{
			throw Exception("Keyring - Key name not found.");
		}

		return it->second.get().GetPkey();
	}


	const PKeyType& operator[](const SimpleObjects::Bytes& keyHash) const
	{
		auto it = m_keyHashMap.find(keyHash);
		if (it == m_keyHashMap.end())
		{
			throw Exception("Keyring - Key hash not found.");
		}

		return it->second.get().GetPkey();
	}


	std::vector<uint8_t> GenKeyHashList() const
	{
		// lock the keyring before hashing
		LockKeyringIfNot();

		std::vector<uint8_t> res;
		res.reserve(m_keyHashMap.size() * 32UL);
		for (const auto& key : m_keyHashMap)
		{
			res.insert(
				res.end(),
				key.first.data(),
				key.first.data() + key.first.size()
			);
		}

		return res;
	}


	std::array<uint8_t, 32UL> GenHash() const
	{
		using _Hasher = mbedTLScpp::Hasher<mbedTLScpp::HashType::SHA256>;

		auto hashList = GenKeyHashList();

		auto hash = _Hasher().Calc(
			mbedTLScpp::CtnFullR(hashList)
		);

		return hash.m_data;
	}


	std::string GenHashHex() const
	{
		std::string hex = cppcodec::hex_lower::encode(GenHash());
		return hex;
	}


	bool IsRegistered(const SimpleObjects::Bytes& keyHash) const
	{
		return m_keyHashMap.find(keyHash) != m_keyHashMap.end();
	}


	bool IsRegistered(const std::array<uint8_t, 32UL>& keyHash) const
	{
		return IsRegistered(
			SimpleObjects::Bytes(keyHash.cbegin(), keyHash.cend())
		);
	}


	template<
		typename T,
		typename std::enable_if<
			std::is_base_of<KeyringKey, T>::value,
			int
		>::type = 0
	>
	void RegisterKey()
	{
		const KeyringKey& key = T::GetInstance();

		RegisterKey(key.GetName(), key);
	}


protected:


	Keyring() :
		m_isLocked(false),
		m_keyNameMap(),
		m_keyHashMap()
	{}


	void LockKeyringIfNot() const
	{
		if (!m_isLocked)
		{
			LockKeyring();
		}
	}


	void LockKeyring() const
	{
		std::lock_guard<std::mutex> lock(m_mapMutex);
		m_isLocked = true;
	}


	void RegisterKey(const std::string& keyName, const KeyringKey& key)
	{
		// this ensures if there are multiple thread, the other thread is
		// locking the keyring after this function passed m_isLocked check
		std::lock_guard<std::mutex> lock(m_mapMutex);

		if (m_isLocked)
		{
			throw Exception("Keyring - Keyring is locked.");
		}

		auto keyHash = key.GetKeySha256();
		SimpleObjects::Bytes keyHashBytes(keyHash.cbegin(), keyHash.cend());

		auto nameMapIt = m_keyNameMap.find(keyName);
		if (nameMapIt != m_keyNameMap.end())
		{
			throw Exception("Keyring - Key name already exists.");
		}

		auto hashMapIt = m_keyHashMap.find(keyHashBytes);
		if (hashMapIt != m_keyHashMap.end())
		{
			throw Exception("Keyring - Key hash already exists.");
		}

		m_keyNameMap.emplace(keyName, std::cref(key));
		m_keyHashMap.emplace(keyHashBytes, std::cref(key));
	}


private:

	mutable std::atomic_bool m_isLocked;
	mutable std::mutex m_mapMutex;
	std::unordered_map<std::string, KeyReference> m_keyNameMap;
	std::map<SimpleObjects::Bytes, KeyReference> m_keyHashMap;

}; // class Keyring


bool KeyringKey::IsRegistered(const Keyring& kr) const
{
	return kr.IsRegistered(GetKeySha256());
}


} // namespace Common
} // namespace DecentEnclave


#define DECENTENCLAVE_KEYRING_KEY(KEY_NAME, KEY_TYPE, PUB_KEY_TYPE) \
class DecentKey_##KEY_NAME : \
	public ::DecentEnclave::Common::KeyringKey \
{ \
public: \
	static_assert( \
		std::is_base_of<::mbedTLScpp::PKeyBase<>, PUB_KEY_TYPE>::value, \
		#PUB_KEY_TYPE " must be a child type of mbedTLScpp::PKeyBase<>" \
	); \
	static_assert( \
		std::is_base_of<PUB_KEY_TYPE, KEY_TYPE>::value, \
		#KEY_TYPE " must be a child type of " #PUB_KEY_TYPE \
	); \
	static const DecentKey_##KEY_NAME& GetInstance() \
	{ \
		static DecentKey_##KEY_NAME s_inst; \
		return s_inst; \
	} \
	static void Register() \
	{ \
		auto& kr = ::DecentEnclave::Common::Keyring::GetMutableInstance(); \
		kr.RegisterKey<DecentKey_##KEY_NAME>(); \
	} \
	static const KEY_TYPE& GetKey() \
	{ \
		const auto& kr = ::DecentEnclave::Common::Keyring::GetInstance(); \
		GetInstance().CheckRegistration(kr); \
		return GetInstance().m_key; \
	} \
	static const PUB_KEY_TYPE& GetPubKey() \
	{ \
		const auto& kr = ::DecentEnclave::Common::Keyring::GetInstance(); \
		GetInstance().CheckRegistration(kr); \
		return GetInstance().m_key; \
	} \
private: \
	static KEY_TYPE ConstructKey(); \
	DecentKey_##KEY_NAME() : \
		m_name(#KEY_NAME), \
		m_key(ConstructKey()) \
	{} \
	std::string m_name; \
	KEY_TYPE m_key; \
public: \
	virtual ~DecentKey_##KEY_NAME() = default; \
	virtual const PKeyType& GetPkey() const override \
	{ \
		return m_key; \
	} \
	virtual const std::string& GetName() const override \
	{ \
		return m_name; \
	} \
}; \
KEY_TYPE DecentKey_##KEY_NAME::ConstructKey()

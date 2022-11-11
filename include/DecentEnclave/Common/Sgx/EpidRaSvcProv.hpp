// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


/* TODO:
#if defined(DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED) || \
	defined(DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED)
*/


#include <cstdint>

#include <memory>
#include <type_traits>

#include <cppcodec/base64_default_rfc4648.hpp>
#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/SecretArray.hpp>
#include <mbedTLScpp/Hkdf.hpp>
#include <SimpleJson/SimpleJson.hpp>
#include <SimpleObjects/SimpleObjects.hpp>
#include <sgx_ukey_exchange.h>

#include "../Platform/Print.hpp"
#include "AttestationConfig.hpp"
#include "Crypto.hpp"
#include "EpidMessages.hpp"
#include "IasRequester.hpp"


namespace DecentEnclave
{
namespace Common
{
namespace Sgx
{


class EpidRaSvcProvCore
{
public: // static members:

	enum class HSState : uint8_t
	{
		Initial,
		Msg0rSent,
		Msg2Sent,
		HandshakeDone,
	};

	using SKey128Bit = mbedTLScpp::SecretArray<uint8_t, 16>;
	using SKey256Bit = mbedTLScpp::SecretArray<uint8_t, 32>;
	using EcKeyPairType = mbedTLScpp::EcKeyPair<mbedTLScpp::EcType::SECP256R1>;
	using EcPubKeyType = mbedTLScpp::EcPublicKey<mbedTLScpp::EcType::SECP256R1>;

	static constexpr size_t sk_iasNonceLen = 32;


	static std::string BuildNonce(
		mbedTLScpp::RbgInterface& randGen,
		size_t len = sk_iasNonceLen
	)
	{
		// NOTE: since the length of the nonce field is defined as the number
		//       of characters in the nonce field of the *JSON* message,
		//       thus, we can't put binary data into the nonce field.

		std::vector<uint8_t> randBytes(len / 2);
		randGen.Rand(randBytes.data(), randBytes.size());

		std::string res;
		res.reserve(len);
		SimpleObjects::Internal::BytesToHEX<false, char>(
			std::back_inserter(res),
			randBytes.begin(),
			randBytes.end()
		);

		return res;
	}


public:

	EpidRaSvcProvCore(
		std::shared_ptr<EcKeyPairType> mySignKey,
		sgx_spid_t spid,
		std::unique_ptr<Common::Sgx::IasRequester> iasReq,
		mbedTLScpp::RbgInterface& randGen
	) :
		m_mySignKey(std::move(mySignKey)),
		m_myEncKey(EcKeyPairType::Generate(randGen)),
		m_peerEncrKey(),
		m_smk(),
		m_mk(),
		m_sk(),
		m_vk(),
		m_spid(spid),
		m_nonce(BuildNonce(randGen)),
		m_iasReq(std::move(iasReq)),
		m_handshakeState(HSState::Initial)
	{
		if (m_mySignKey == nullptr)
		{
			throw InvalidArgumentException("The given key pair is null");
		}
	}


	virtual ~EpidRaSvcProvCore() = default;


	EpidRaSvcProvCore(const EpidRaSvcProvCore& rhs) = delete;


	EpidRaSvcProvCore(EpidRaSvcProvCore&& rhs) :
		m_mySignKey(std::move(rhs.m_mySignKey)),
		m_myEncKey(std::move(rhs.m_myEncKey)),
		m_peerEncrKey(std::move(rhs.m_peerEncrKey)),
		m_smk(std::move(rhs.m_smk)),
		m_mk(std::move(rhs.m_mk)),
		m_sk(std::move(rhs.m_sk)),
		m_vk(std::move(rhs.m_vk)),
		m_spid(std::move(rhs.m_spid)),
		m_nonce(std::move(rhs.m_nonce)),
		m_iasReq(std::move(rhs.m_iasReq)),
		m_handshakeState(rhs.m_handshakeState)
	{
		rhs.m_handshakeState = HSState::Initial;
	}


	virtual bool IsHandshakeDone() const
	{
		return m_handshakeState == HSState::HandshakeDone;
	}


	const std::string& GetNonce() const
	{
		return m_nonce;
	}


//==========
// EPID protocol messages
//==========


	virtual decent_ra_msg0r_t GetMsg0r(const decent_ra_msg0s_t& msg0s)
	{
		if (!ValidateExtGrpId(msg0s.extended_grp_id))
		{
			throw InvalidArgumentException(
				"The given extended group ID is unsupported"
			);
		}

		decent_ra_msg0r_t res;
		ImportEcKey(res.sp_pub_key, *m_mySignKey);

		m_handshakeState = HSState::Msg0rSent;

		return res;
	}


	virtual std::vector<uint8_t> GetMsg2(
		const sgx_ra_msg1_t& msg1,
		mbedTLScpp::RbgInterface& randGen
	)
	{
		using Hasher = mbedTLScpp::Hasher<mbedTLScpp::HashType::SHA256>;
		using Cmacer = mbedTLScpp::Cmacer<
			mbedTLScpp::CipherType::AES,
			128,
			mbedTLScpp::CipherMode::ECB
		>;

		int mbedRet = 0;
		std::vector<uint8_t> res;

		SetPeerEncrPubKey(msg1.g_a, randGen);

		res.resize(sizeof(sgx_ra_msg2_t));
		sgx_ra_msg2_t& msg2Ref = *reinterpret_cast<sgx_ra_msg2_t*>(res.data());

		sgx_ec256_public_t myEncSgxKey;
		ImportEcKey(myEncSgxKey, m_myEncKey);
		msg2Ref.g_b = myEncSgxKey;
		msg2Ref.spid = m_spid;
		msg2Ref.quote_type = AttestationConfig::sk_quoteTypeLinkable;
		msg2Ref.kdf_id = AttestationConfig::sk_kdfIdDefault;

		auto hashToBeSigned = Hasher().Calc(
			mbedTLScpp::CtnFullR(myEncSgxKey.gx),
			mbedTLScpp::CtnFullR(myEncSgxKey.gy),
			mbedTLScpp::CtnFullR(m_peerEncrKey.gx),
			mbedTLScpp::CtnFullR(m_peerEncrKey.gy)
		);

		mbedTLScpp::BigNum rBN;
		mbedTLScpp::BigNum sBN;
		std::tie(rBN, sBN) = m_mySignKey->SignInBigNum(hashToBeSigned, randGen);

		mbedRet = mbedtls_mpi_write_binary_le(
			rBN.Get(),
			reinterpret_cast<uint8_t*>(msg2Ref.sign_gb_ga.x),
			sizeof(msg2Ref.sign_gb_ga.x)
		);
		mbedTLScpp::CheckMbedTlsIntRetVal(
			mbedRet,
			"mbedtls_mpi_write_binary_le",
			"DecentEnclave::Common::Sgx::EpidRaSvcProvCore::GetMsg2"
		);
		mbedRet = mbedtls_mpi_write_binary_le(
			sBN.Get(),
			reinterpret_cast<uint8_t*>(msg2Ref.sign_gb_ga.y),
			sizeof(msg2Ref.sign_gb_ga.y)
		);
		mbedTLScpp::CheckMbedTlsIntRetVal(
			mbedRet,
			"mbedtls_mpi_write_binary_le",
			"DecentEnclave::Common::Sgx::EpidRaSvcProvCore::GetMsg2"
		);

		const size_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
		std::vector<uint8_t> tmpCmacData(cmac_size);
		std::memcpy(tmpCmacData.data(), &(msg2Ref.g_b), tmpCmacData.size());

		auto cmacRes = Cmacer(mbedTLScpp::CtnFullR(m_smk)).Calc(
			mbedTLScpp::CtnFullR(tmpCmacData)
		);
		static_assert(
			std::tuple_size<decltype(cmacRes)>::value == sizeof(msg2Ref.mac),
			"CMAC result size doesn't match"
		);
		std::memcpy(msg2Ref.mac, cmacRes.data(), cmacRes.size());

		std::string sigrlB64 = m_iasReq->GetSigrl(msg1.gid);
		Common::Platform::Print::StrDebug("SigRL: " + sigrlB64);
		std::vector<uint8_t> sigRL =
			cppcodec::base64_rfc4648::decode(sigrlB64);

		msg2Ref.sig_rl_size = static_cast<uint32_t>(sigRL.size());
		res.insert(res.end(), sigRL.begin(), sigRL.end());

		m_handshakeState = HSState::Msg2Sent;
		return res;
	}


	virtual void ProcMsg3(
		const std::vector<uint8_t>& msg3
	)
	{
		if (msg3.size() < sizeof(sgx_ra_msg3_t))
		{
			throw Common::InvalidArgumentException(
				"msg3 is too short (size = " + std::to_string(msg3.size()) + ")"
			);
		}

		const sgx_ra_msg3_t& msg3Ref =
			*reinterpret_cast<const sgx_ra_msg3_t*>(msg3.data());

		auto iasReqBody = BuildIasReportReqBody(msg3Ref, msg3.size(), m_nonce);
		Common::Platform::Print::StrDebug("IAS report request: " + iasReqBody);

		std::string iasReport = m_iasReq->GetReport(iasReqBody);
		Common::Platform::Print::StrDebug("IAS report: " + iasReport);
	}

protected:

	virtual bool ValidateExtGrpId(uint32_t extGrpId) const
	{
		return extGrpId == 0;
	}


	void SetPeerEncrPubKey(
		const sgx_ec256_public_t & inEncrPubKey,
		mbedTLScpp::RbgInterface& randGen
	)
	{
		m_peerEncrKey = inEncrPubKey;

		EcPubKeyType peerEncKey(mbedTLScpp::EcType::SECP256R1);
		ExportEcKey(peerEncKey, m_peerEncrKey);

		auto sharedKeyInt =
			m_myEncKey.DeriveSharedKeyInBigNum(peerEncKey, randGen);

		SKey256Bit sharedKey;
		int mbedRet = mbedtls_mpi_write_binary_le(
			sharedKeyInt.Get(),
			sharedKey.data(),
			sharedKey.size()
		);
		mbedTLScpp::CheckMbedTlsIntRetVal(
			mbedRet,
			"mbedtls_mpi_write_binary_le",
			"DecentEnclave::Common::Sgx::EpidRaSvcProvCore::SetPeerEncrPubKey"
		);


		m_smk = Ckdf<mbedTLScpp::CipherType::AES, 128, mbedTLScpp::CipherMode::ECB>(
			CtnFullR(sharedKey), "SMK"
		);
		m_mk  = Ckdf<mbedTLScpp::CipherType::AES, 128, mbedTLScpp::CipherMode::ECB>(
			CtnFullR(sharedKey), "MK"
		);
		m_sk  = Ckdf<mbedTLScpp::CipherType::AES, 128, mbedTLScpp::CipherMode::ECB>(
			CtnFullR(sharedKey), "SK"
		);
		m_vk  = Ckdf<mbedTLScpp::CipherType::AES, 128, mbedTLScpp::CipherMode::ECB>(
			CtnFullR(sharedKey), "VK"
		);
	}

	static std::string BuildIasReportReqBody(
		const sgx_ra_msg3_t& msg3,
		const size_t msg3Size,
		const std::string& nonce
	)
	{
		using _PsSecDescType =
			typename std::remove_reference<
				decltype(msg3.ps_sec_prop.sgx_ps_sec_prop_desc)
			>::type;
		static_assert(
			std::is_same<uint8_t[256], _PsSecDescType>::value,
			"Unexpected type of sgx_ps_sec_prop_desc_t"
		);

		static const std::array<uint8_t, sizeof(sgx_ps_sec_prop_desc_t)>
			sk_zeroSecPropDesc = { 0 };
		static const SimpleObjects::String sk_labelQuote = "isvEnclaveQuote";
		static const SimpleObjects::String sk_labelNonce = "nonce";
		static const SimpleObjects::String sk_labelPseMa = "pseManifest";


		const uint8_t* quotePtr = reinterpret_cast<const uint8_t*>(&msg3.quote);
		std::vector<uint8_t> quote(
			quotePtr,
			quotePtr + (msg3Size - sizeof(sgx_ra_msg3_t))
		);

		// check msg3.ps_sec_prop.sgx_ps_sec_prop_desc to see if was PSE enabled
		std::string pseManifestStr;
		if (
			!std::equal(
				sk_zeroSecPropDesc.cbegin(),
				sk_zeroSecPropDesc.cend(),
				std::begin(msg3.ps_sec_prop.sgx_ps_sec_prop_desc)
			)
		)
		{
			// PSE manifest presents
			pseManifestStr = cppcodec::base64_rfc4648::encode(
				msg3.ps_sec_prop.sgx_ps_sec_prop_desc
			);
		}
		else
		{
			Common::Platform::Print::StrDebug("PSE is not enabled during RA");
		}

		auto jsonObj = SimpleObjects::Dict();
		jsonObj[sk_labelQuote] = SimpleObjects::String(
				cppcodec::base64_rfc4648::encode(quote)
			);
		jsonObj[sk_labelNonce] = SimpleObjects::String(nonce);
		if (!pseManifestStr.empty())
		{
			jsonObj[sk_labelPseMa] = SimpleObjects::String(pseManifestStr);
		}

		std::string json = SimpleJson::DumpStr(jsonObj);

		return json;
	}

private:

	std::shared_ptr<EcKeyPairType> m_mySignKey;
	EcKeyPairType m_myEncKey;
	sgx_ec256_public_t m_peerEncrKey;
	SKey128Bit m_smk;
	SKey128Bit m_mk;
	SKey128Bit m_sk;
	SKey128Bit m_vk;
	sgx_spid_t m_spid;
	std::string m_nonce;
	std::unique_ptr<Common::Sgx::IasRequester> m_iasReq;
	HSState m_handshakeState;

}; // class EpidRaSvcProvCore


} // namespace Sgx
} // namespace Common
} // namespace DecentEnclave

// #endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED || _UNTRUSTED

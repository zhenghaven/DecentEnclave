// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED

#include <functional>

#include <sgx_dh.h>
#include <mbedTLScpp/SKey.hpp>

#include "../../Common/AesGcmSocketHandshaker.hpp"
#include "../../Common/Sgx/Crypto.hpp"
#include "../../Common/Sgx/Exceptions.hpp"


namespace DecentEnclave
{
namespace Trusted
{
namespace Sgx
{


class LaInitiator :
	public Common::AesGcmSocketHandshaker
{
public: // static members:

	enum class HSState : uint8_t
	{
		Initial,
		Msg2Sent,
		HandshakeDone,
	}; // enum class HSState

	using PeerIdVrfyCallback =
		std::function<void(const sgx_dh_session_enclave_identity_t&)>;

public:

	LaInitiator(
		PeerIdVrfyCallback peerIdVrfyCallback = PeerIdVrfyCallback()
	) :
		m_session(),
		m_state(HSState::Initial),
		m_aek(),
		m_peerId(),
		m_peerIdVrfyCallback(std::move(peerIdVrfyCallback))
	{
		sgx_status_t sgxRet =
			sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &m_session);
		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			sgx_dh_init_session
		);
	}


	LaInitiator(const LaInitiator& rhs) = delete;


	// LCOV_EXCL_START
	virtual ~LaInitiator() = default;
	// LCOV_EXCL_STOP


	sgx_dh_msg2_t ProcMsg1(const sgx_dh_msg1_t& msg1)
	{
		sgx_dh_msg2_t msg2;
		sgx_status_t sgxRet =
			sgx_dh_initiator_proc_msg1(&msg1, &msg2, &m_session);
		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			sgx_dh_responder_gen_msg1
		);

		m_state = HSState::Msg2Sent;

		return msg2;
	}


	void ProcMsg3(const sgx_dh_msg3_t& msg3)
	{
		uint8_t* aekPtr = m_aek.data();
		unsigned char (*aekArrPtr)[16] =
			reinterpret_cast<unsigned char(*)[16]>(aekPtr);

		sgx_status_t sgxRet =
			sgx_dh_initiator_proc_msg3(
				&msg3,
				&m_session,
				aekArrPtr,
				&m_peerId
			);
		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			sgx_dh_initiator_proc_msg3
		);

		if (m_peerIdVrfyCallback)
		{
			m_peerIdVrfyCallback(m_peerId);
		}

		m_state = HSState::HandshakeDone;
	}


	virtual mbedTLScpp::SKey<128> GetSecretKey128() const override
	{
		static constexpr const char sk_label[] = "SK";

		return Common::Sgx::Ckdf<
			mbedTLScpp::CipherType::AES,
			128,
			mbedTLScpp::CipherMode::ECB
		>(CtnFullR(m_aek), sk_label);
	}


	virtual mbedTLScpp::SKey<128> GetMaskKey128() const override
	{
		static constexpr const char sk_label[] = "MK";

		return Common::Sgx::Ckdf<
			mbedTLScpp::CipherType::AES,
			128,
			mbedTLScpp::CipherMode::ECB
		>(CtnFullR(m_aek), sk_label);
	}


	virtual bool IsHandshakeDone() const override
	{
		return m_state == HSState::HandshakeDone;
	}


	virtual void HandshakeStep(SimpleSysIO::StreamSocketBase& sock) override
	{
		switch (m_state)
		{
		case HSState::Initial:
		{
			sgx_dh_msg1_t peerMsg1 = sock.RecvPrimitive<sgx_dh_msg1_t>();

			sgx_dh_msg2_t msg2 = ProcMsg1(peerMsg1);

			sock.SendPrimitive(msg2);

			return;
		}
		case HSState::Msg2Sent:
		{
			sgx_dh_msg3_t peerMsg3 = sock.RecvPrimitive<sgx_dh_msg3_t>();

			ProcMsg3(peerMsg3);

			return;
		}
		default:
			throw Common::Exception(
				"LaInitiator::HandshakeStep - "
				"Invalid handshake state"
			);
		}
	}


private:

	sgx_dh_session_t m_session;
	HSState m_state;
	mbedTLScpp::SKey<128> m_aek;
	sgx_dh_session_enclave_identity_t m_peerId;
	PeerIdVrfyCallback m_peerIdVrfyCallback;

}; // class LaInitiator


} // namespace Sgx
} // namespace Trusted
} // namespace DecentEnclave

#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED

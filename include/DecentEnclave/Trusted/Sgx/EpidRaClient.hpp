// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


// TODO: #ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED

#include <cstdint>

#include <memory>
#include <vector>

#include <mbedTLScpp/SecretArray.hpp>
#include <mbedTLScpp/Hash.hpp>
#include <sgx_tkey_exchange.h>


#include "../../Common/Platform/Print.hpp"
#include "../../Common/Sgx/Exceptions.hpp"

#include "decent_tkey_exchange.hpp"
#include "EpidSvcProvAuth.hpp"
#include "UntrustedBuffer.hpp"


//==========
// Our EDL functions
//==========
extern "C"
sgx_status_t
ocall_decent_attest_get_extended_epid_grp_id(
	sgx_status_t* retval,
	uint32_t* extGrpId
);

extern "C"
sgx_status_t
ocall_decent_attest_get_msg1(
	sgx_status_t* retval,
	uint64_t enclave_id,
	uint32_t ra_ctx,
	sgx_ra_msg1_t* msg1
);

extern "C"
sgx_status_t
ocall_decent_attest_get_msg3(
	sgx_status_t* retval,
	uint64_t enclave_id,
	uint32_t ra_ctx,
	const sgx_ra_msg2_t* msg2,
	size_t msg2_size,
	uint8_t** out_msg3,
	size_t* out_msg3_size
);


namespace DecentEnclave
{
namespace Trusted
{
namespace Sgx
{


class EpidRaClientCore
{
public: // static members:

	enum class HSState : uint8_t
	{
		Initial,
		Msg0sSent,
		RaCtxInit,
		Msg1Sent,
		Msg3Sent,
		HandshakeDone,
	};

	using SKey128Bit = mbedTLScpp::SecretArray<uint8_t, 16>;

public:
	EpidRaClientCore(
		uint64_t enclaveId,
		const std::vector<uint8_t>& addReportData,
		std::unique_ptr<EpidSvcProvAuth> svcProvAuth
	) :
		m_enclaveId(enclaveId),
		m_raCtx(),
		m_addReportData(addReportData),
		m_peerSignKey(),
		m_svcProvAuth(std::move(svcProvAuth)),
		m_mk(),
		m_sk(),
		m_handshakeState(HSState::Initial)
	{}


	virtual ~EpidRaClientCore()
	{
		if (m_handshakeState >= HSState::RaCtxInit)
		{
			decent_ra_close(m_raCtx);
		}
	}


	EpidRaClientCore(const EpidRaClientCore& other) = delete;


	EpidRaClientCore(EpidRaClientCore&& other) :
		m_enclaveId(other.m_enclaveId),
		m_raCtx(other.m_raCtx),
		m_addReportData(std::move(other.m_addReportData)),
		m_peerSignKey(std::move(other.m_peerSignKey)),
		m_svcProvAuth(std::move(other.m_svcProvAuth)),
		m_mk(std::move(other.m_mk)),
		m_sk(std::move(other.m_sk)),
		m_handshakeState(other.m_handshakeState)
	{
		other.m_handshakeState = HSState::Initial;
	}


	virtual bool IsHandshakeDone() const
	{
		return m_handshakeState == HSState::HandshakeDone;
	}


	virtual bool CalcReportData(
		const sgx_report_data_t& stdData,
		sgx_report_data_t& finalData
	) const
	{
		if (m_addReportData.size() == 0)
		{
			// No additional data to add
			finalData = stdData;
			return true;
		}

		auto hash = mbedTLScpp::Hasher<mbedTLScpp::HashType::SHA256>().Calc(
			mbedTLScpp::CtnFullR(stdData.d),
			mbedTLScpp::CtnFullR(m_addReportData)
		);

		std::copy(
			hash.m_data.cbegin(),
			hash.m_data.cend(),
			std::begin(finalData.d)
		);

		return true;
	}


//==========
// EPID protocol messages
//==========


	virtual decent_ra_msg0s_t GetMsg0s()
	{
		decent_ra_msg0s_t res;

		sgx_status_t funcRet = SGX_ERROR_UNEXPECTED;
		sgx_status_t edgeRet =
			ocall_decent_attest_get_extended_epid_grp_id(
				&funcRet,
				&res.extended_grp_id
			);
		DECENT_ENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			edgeRet,
			ocall_decent_attest_get_extended_epid_grp_id
		);
		DECENT_ENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			funcRet,
			ocall_decent_attest_get_extended_epid_grp_id
		);

		m_handshakeState = HSState::Msg0sSent;

		return res;
	}


	virtual sgx_ra_msg1_t GetMsg1(const decent_ra_msg0r_t& msg0r)
	{
		if (!m_svcProvAuth->Authenticate(msg0r.sp_pub_key))
		{
			throw Common::InvalidArgumentException(
				"Failed to authenticate service provider's signing key"
			);
		}
		m_peerSignKey = msg0r.sp_pub_key;

		sgx_status_t sgxRet = SGX_ERROR_UNEXPECTED;
		sgx_status_t funcRet = SGX_ERROR_UNEXPECTED;

		//=====
		// Initialize RA context
		//=====
		auto repDataFunc =
			[this](
				const sgx_report_data_t& stdData,
				sgx_report_data_t& finalData
			){
				return this->CalcReportData(stdData, finalData);
			};

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
		sgxRet = sgx_create_pse_session();
		DECENT_ENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			sgx_create_pse_session
		);
#endif //defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
		sgxRet = decent_ra_init(
			&m_peerSignKey,
			1, /* deprecated */
			repDataFunc,
			&m_raCtx
		);
		DECENT_ENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			decent_ra_init
		);
		m_handshakeState = HSState::RaCtxInit;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
		sgx_close_pse_session();
#endif //defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)


		//=====
		// Get msg1
		//=====
		sgx_ra_msg1_t res;
		sgxRet = ocall_decent_attest_get_msg1(
			&funcRet,
			m_enclaveId,
			m_raCtx,
			&res
		);
		DECENT_ENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			ocall_decent_attest_get_msg1
		);
		DECENT_ENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			funcRet,
			ocall_decent_attest_get_msg1
		);
		m_handshakeState = HSState::Msg1Sent;

		return res;
	}


	virtual std::vector<uint8_t> GetMsg3(const std::vector<uint8_t>& msg2)
	{
		using _UBuffer = UntrustedBuffer<uint8_t>;

		sgx_status_t sgxRet = SGX_ERROR_UNEXPECTED;
		sgx_status_t funcRet = SGX_ERROR_UNEXPECTED;
		_UBuffer uBuf;

		if (msg2.size() < sizeof(sgx_ra_msg2_t))
		{
			throw Common::InvalidArgumentException(
				"msg2 is too short (size = " + std::to_string(msg2.size()) + ")"
			);
		}

		sgxRet = ocall_decent_attest_get_msg3(
			&funcRet,
			m_enclaveId,
			m_raCtx,
			reinterpret_cast<const sgx_ra_msg2_t*>(msg2.data()),
			msg2.size(),
			&(uBuf.m_data),
			&(uBuf.m_size)
		);
		DECENT_ENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			ocall_decent_attest_get_msg3
		);
		DECENT_ENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			funcRet,
			ocall_decent_attest_get_msg3
		);

		std::vector<uint8_t> res =uBuf.CopyToContainer<std::vector<uint8_t> >();

		GetKeys();

		m_handshakeState = HSState::Msg3Sent;

		return res;
	}

	// const sgx_ias_report_t& GetIasReport();


private:

	void GetKeys()
	{
		sgx_status_t sgxRet = SGX_ERROR_UNEXPECTED;

		sgxRet = decent_ra_get_keys(
			m_raCtx,
			SGX_RA_KEY_SK,
			reinterpret_cast<sgx_ec_key_128bit_t*>(m_sk.data())
		);
		DECENT_ENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			decent_ra_get_keys
		);

		sgxRet = decent_ra_get_keys(
			m_raCtx,
			SGX_RA_KEY_MK,
			reinterpret_cast<sgx_ec_key_128bit_t*>(m_mk.data())
		);
		DECENT_ENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			sgxRet,
			decent_ra_get_keys
		);
	}

	// virtual void InitRaContext(const sgx_ra_config& raConfig, const sgx_ec256_public_t& pubKey);
	// virtual void CloseRaContext();
	// virtual bool CheckKeyDerivationFuncId(const uint16_t id) const;
	// virtual void DeriveSharedKeys(SKey128Bit& mk, SKey128Bit& sk);
	// virtual void GetMsg1(sgx_ra_msg1_t& msg1);

	uint64_t m_enclaveId;
	sgx_ra_context_t m_raCtx;
	std::vector<uint8_t> m_addReportData;

	sgx_ec256_public_t m_peerSignKey;
	std::unique_ptr<EpidSvcProvAuth> m_svcProvAuth;

	SKey128Bit m_mk;
	SKey128Bit m_sk;

	// sgx_ra_config m_raConfig;
	// sgx_ec256_public_t m_peerSignKey;
	// sgx_ias_report_t m_iasReport;

	HSState m_handshakeState;


}; // class EpidRaClientCore


} // namespace Sgx
} // namespace Trusted
} // namespace DecentEnclave

// TODO: #endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED

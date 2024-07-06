// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstdint>

#include <string>
#include <vector>

#include "../Common/AesGcmStreamSocket.hpp"
#include "../Common/CertStore.hpp"
#include "../Common/DecentCerts.hpp"
#include "../Common/Internal/SimpleJson.hpp"
#include "../Common/Internal/SimpleObj.hpp"
#include "../Common/Keyring.hpp"
#include "../Common/KeyringKey.hpp"
#include "../Common/Logging.hpp"
#include "../Common/Platform/Random.hpp"
#include "AuthListMgr.hpp"
#include "ComponentConnection.hpp"
#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
#include "Sgx/LaInitiator.hpp"
#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED

#include <mbedTLScpp/X509Req.hpp>


namespace DecentEnclave
{
namespace Trusted
{


class AppCertRequester
{
public: // static members:

	using KeyringType    = Common::Keyring;
	using KeyType        = Common::KeyringKey::PKeyType;
	using SecSocketWrap  = Common::AesGcmStreamSocket<128>;
	using RandType       = Common::Platform::RandGenerator;
	using HandshakerType = Common::AesGcmSocketHandshaker<128>;

	static std::vector<uint8_t> GenerateCSR(
		const KeyType& key
	)
	{
		RandType rand;

		mbedTLScpp::X509ReqWriter writer(
			mbedTLScpp::HashType::SHA256,
			key,
			"CN=DecentApp,O=DecentEnclave,OU=DecentApp"
		);

		return writer.GetDer(rand);
	}

public:

	AppCertRequester(
		const std::string& svrName,
		const std::string& keyName
	) :
		AppCertRequester(svrName, keyName, keyName)
	{}

	AppCertRequester(
		const std::string& svrName,
		const std::string& keyName,
		const std::string& certName
	) :
		m_logger(Common::LoggerFactory::GetLogger("DecentEnclave::Trusted::AppCertRequester")),
		m_svrName(svrName),
		m_keyName(keyName),
		m_certName(certName),
		m_csr(GenerateCSR(KeyringType::GetInstance()[keyName].GetPkey())),
		m_appCertReq(BuildAppCertReq(m_keyName, m_csr))
	{}

	~AppCertRequester() = default;

	std::string Request()
	{
		static const std::string sk_reqBody = "{\"method\":\"req_app_cert\"}";

		auto socket = ComponentConnection::Connect(m_svrName);
		socket->SizedSendBytes(sk_reqBody);

		auto secSocket =
			SecSocketWrap::FromHandshake(
				BuildHandshake(),
				std::move(socket),
				Common::Internal::Obj::Internal::make_unique<RandType>()
			);

		secSocket->SizedSendBytes(m_appCertReq);

		auto pem = secSocket->SizedRecvBytes<std::string>();

		m_logger.Info("App certificate received:\n" + pem);

		return pem;
	}

	std::string GetServerCert()
	{
		const std::string reqBody = BuildSvrCertReq(m_keyName);

		auto socket = ComponentConnection::Connect(m_svrName);
		socket->SizedSendBytes(reqBody);

		auto resJson = socket->SizedRecvBytes<std::string>();
		std::string pem = ReadSvrCertResult(resJson);

		m_logger.Info("Server Certificate received:\n" + pem);

		return pem;
	}

private:

	static std::vector<uint8_t> BuildAppCertReq(
		const std::string& keyName,
		const std::vector<uint8_t>& csr
	)
	{
		Common::AppCertRequest certReq;
		certReq.get_KeyName() = keyName;
		certReq.get_CSR() = Common::Internal::Obj::Bytes(csr);
		certReq.get_AuthList() = Common::Internal::Obj::Bytes(
			AuthListMgr::GetInstance().GetAuthListAdvRlp()
		);

		return AdvancedRlp::GenericWriter::Write(certReq);
	}

	static std::string BuildSvrCertReq(const std::string& keyName)
	{
		using _ObjString = Common::Internal::Obj::String;
		using _ObjList = Common::Internal::Obj::List;
		Common::Internal::Obj::Dict obj;
		obj[_ObjString("method")] = _ObjString("get_svr_cert");
		obj[_ObjString("params")] = _ObjList({
			_ObjString(keyName)
		});

		return Common::Internal::Json::DumpStr(obj);
	}

	static std::string ReadSvrCertResult(const std::string& resJson)
	{
		using _ObjString = Common::Internal::Obj::String;

		auto resObj = Common::Internal::Json::LoadStr(resJson);
		const auto& resDict = resObj.AsDict();
		const auto& resStr = resDict[_ObjString("result")].AsString();

		return std::string(resStr.data(), resStr.data() + resStr.size());
	}

#ifdef DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED
	std::unique_ptr<HandshakerType> BuildHandshake()
	{
		using LaInitiator = Sgx::LaInitiator;

		return Common::Internal::Obj::Internal::make_unique<LaInitiator>();
	}
#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED

	using _LoggerType = typename Common::LoggerFactory::LoggerType;

	_LoggerType m_logger;

	std::string m_svrName;
	std::string m_keyName;
	std::string m_certName;

	std::vector<uint8_t> m_csr;
	std::vector<uint8_t> m_appCertReq;

}; // class AppCertRequester


} // namespace Trusted
} // namespace DecentEnclave

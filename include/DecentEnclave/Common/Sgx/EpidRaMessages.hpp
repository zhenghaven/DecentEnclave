// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstdint>

#include <tuple>

#include <mbedTLScpp/X509Cert.hpp>
#include <sgx_tcrypto.h>
#include <SimpleRlp/SimpleRlp.hpp>


#if defined(DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED) || \
	defined(DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED)

#pragma pack(push, 1)

typedef struct _decent_ra_msg0s_t
{
	uint32_t  extended_grp_id;
} decent_ra_msg0s_t;

typedef struct _decent_ra_msg0r_t
{
	sgx_ec256_public_t  sp_pub_key;
} decent_ra_msg0r_t;

#pragma pack(pop)





namespace DecentEnclave
{
namespace Common
{
namespace Sgx
{


//==========
// IAS Report Set
//==========


using IasReportSetCore = std::tuple<
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("IasCert")>,
		SimpleObjects::ListT<
			SimpleObjects::Bytes
		>
	>,
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("Report")>,
		SimpleObjects::Bytes
	>,
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("ReportSign")>,
		SimpleObjects::Bytes
	>
>;


class IasReportSet :
	public SimpleObjects::StaticDict<IasReportSetCore>
{
public: // static members:

	using Self = IasReportSet;
	using Base = SimpleObjects::StaticDict<IasReportSetCore>;

	using IasCertType = SimpleObjects::ListT<
		SimpleObjects::Bytes
	>;

public:

	using Base::Base;

	SimpleObjects::Bytes& get_ReportSign()
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("ReportSign")> >();
	}

	const SimpleObjects::Bytes& get_ReportSign() const
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("ReportSign")> >();
	}

	IasCertType& get_IasCert()
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("IasCert")> >();
	}

	const IasCertType& get_IasCert() const
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("IasCert")> >();
	}

	SimpleObjects::Bytes& get_Report()
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("Report")> >();
	}

	const SimpleObjects::Bytes& get_Report() const
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("Report")> >();
	}

}; // class IasReportSet


using IasReportSetParserCore = std::tuple<
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("IasCert")>,
		SimpleRlp::ListParserT<
			SimpleRlp::BytesParser,
			SimpleRlp::FailingParserBytes,
			SimpleObjects::ListT<
				SimpleObjects::Bytes
			>
		>
	>,
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("Report")>,
		SimpleRlp::BytesParser
	>,
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("ReportSign")>,
		SimpleRlp::BytesParser
	>
>;


using IasReportSetParser = SimpleRlp::StaticDictParserT<
	IasReportSetParserCore,
	false, /* No missing items allowed */
	false, /* No extra items allowed */
	IasReportSet
>;


inline std::string GetStrFromSimpleBytes(const SimpleObjects::Bytes& b)
{
	return std::string(
		reinterpret_cast<const char*>(b.data()),
		reinterpret_cast<const char*>(b.data() + b.size())
	);
}


inline SimpleObjects::Bytes GetSimpleBytesFromStr(const std::string& s)
{
	return SimpleObjects::Bytes(
		reinterpret_cast<const uint8_t*>(s.data()),
		reinterpret_cast<const uint8_t*>(s.data() + s.size())
	);
}


inline void X509Cert2DERList(
	Internal::Obj::ListT<Internal::Obj::Bytes>& derList,
	mbedTLScpp::X509Cert& cert
)
{
	bool hasNext = cert.HasNext();
	do
	{
		derList.push_back(
			SimpleObjects::Bytes(
				cert.GetDer()
			)
		);

		hasNext = cert.HasNext();

		if (hasNext)
		{
			cert.NextCert();
		}
	} while (hasNext);
}


inline void CertPEM2DERList(
	Internal::Obj::ListT<Internal::Obj::Bytes>& derList,
	const std::string& pemStr
)
{
	mbedTLScpp::X509Cert iasCertObj =
		mbedTLScpp::X509Cert::FromPEM(pemStr);
	X509Cert2DERList(derList, iasCertObj);
}


inline mbedTLScpp::X509Cert X509CertFromDERList(
	Internal::Obj::ListT<Internal::Obj::Bytes>& derList
)
{
	auto cert = mbedTLScpp::X509Cert::Empty();
	for (const auto& der : derList)
	{
		cert.AppendDER(mbedTLScpp::CtnFullR(der.GetVal()));
	}
	return cert;
}


} // namespace Sgx
} // namespace Common
} // namespace DecentEnclave


#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED || _UNTRUSTED

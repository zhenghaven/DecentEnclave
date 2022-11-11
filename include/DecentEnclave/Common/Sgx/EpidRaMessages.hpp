// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstdint>

#include <tuple>

#include <sgx_tcrypto.h>
#include <AdvancedRlp/AdvancedRlp.hpp>

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
		SimpleObjects::StrKey<SIMOBJ_KSTR("ReportSign")>,
		SimpleObjects::String
	>,
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("IasCert")>,
		SimpleObjects::String
	>,
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("Report")>,
		SimpleObjects::String
	>
>;


class IasReportSet :
	public SimpleObjects::StaticDict<IasReportSetCore>
{
public: // static members:

	using Self = IasReportSet;
	using Base = SimpleObjects::StaticDict<IasReportSetCore>;

public:

	using Base::Base;

	SimpleObjects::String& get_ReportSign()
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("ReportSign")> >();
	}

	const SimpleObjects::String& get_ReportSign() const
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("ReportSign")> >();
	}

	SimpleObjects::String& get_IasCert()
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("IasCert")> >();
	}

	const SimpleObjects::String& get_IasCert() const
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("IasCert")> >();
	}

	SimpleObjects::String& get_Report()
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("Report")> >();
	}

	const SimpleObjects::String& get_Report() const
	{
		return Base::get<SimpleObjects::StrKey<SIMOBJ_KSTR("Report")> >();
	}

}; // class IasReportSet


using IasReportSetParserCore = std::tuple<
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("ReportSign")>,
		AdvancedRlp::CatStringParser
	>,
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("IasCert")>,
		AdvancedRlp::CatStringParser
	>,
	std::pair<
		SimpleObjects::StrKey<SIMOBJ_KSTR("Report")>,
		AdvancedRlp::CatStringParser
	>
>;


using IasReportSetParser = AdvancedRlp::CatStaticDictParserT<
	IasReportSetParserCore,
	false, /* No missing items allowed */
	false, /* No extra items allowed */
	IasReportSet
>;


} // namespace Sgx
} // namespace Common
} // namespace DecentEnclave


#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED || _UNTRUSTED

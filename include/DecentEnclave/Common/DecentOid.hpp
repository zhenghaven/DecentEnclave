// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstdint>

#include <string>
#include <vector>

#include <mbedTLScpp/Internal/Asn1Helper.hpp>


namespace DecentEnclave
{
namespace Common
{

struct DecentOid
{

	// Reference for OID to ASN.1 encoding rules:
	// https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier

	static const std::string& GetAsn1OidUuid()
	{
		static const std::string oidUuid = {
			static_cast<char>(2 * 40 + 25) // 2.25
		};
		return oidUuid;
	}


	static const std::string& GetAsn1OidIdOrg()
	{
		static const std::string oidIdOrg = {
			static_cast<char>(1 * 40 + 3) // 1.3
		};
		return oidIdOrg;
	}


	static const std::string& GetAsn1OidPEN()
	{
		// The PEN prefix is 1.3.6.1.4.1.
		// https://www.iana.org/assignments/enterprise-numbers/
		static const std::string oidPen =
			GetAsn1OidIdOrg() + '\x06' + '\x01' + '\x04' + '\x01';
		return oidPen;
	}


	static std::string BuildDecentLabOid()
	{
		// This is the OID registered via IANA PENs for Decent Lab.
		// https://www.iana.org/assignments/enterprise-numbers/
		std::vector<uint8_t> pen = { 0xF2U, 0x45U, };
		std::string res;

		mbedTLScpp::Internal::Asn1MultiBytesOidEncode<char>(
			std::back_inserter(res),
			pen.cbegin(),
			pen.cend(),
			pen.size()
		);

		return GetAsn1OidPEN() + res;
	}


	static const std::string& GetDecentLabOid()
	{
		static const std::string oid = BuildDecentLabOid();
		return oid;
	}


	static const std::string& GetDecentEnclaveOid()
	{
		static const std::string oid = GetDecentLabOid() + '\x01' + '\x01';

		return oid;
	}


	//==========
	// Root.*
	//==========


	static const std::string& GetVersionOid()
	{
		static const std::string oid = GetDecentEnclaveOid() + '\x01';

		return oid;
	}


	static const std::string& GetEnclaveTypeOid()
	{
		static const std::string oid = GetDecentEnclaveOid() + '\x02';

		return oid;
	}


	static const std::string& GetEnclaveTypeSpecRootOid()
	{
		static const std::string oid = GetDecentEnclaveOid() + '\x03';

		return oid;
	}


	static const std::string& GetKeyringHashOid()
	{
		static const std::string oid = GetDecentEnclaveOid() + '\x04';

		return oid;
	}


	static const std::string& GetAppHashOid()
	{
		static const std::string oid = GetDecentEnclaveOid() + '\x05';

		return oid;
	}


	static const std::string& GetAuthListOid()
	{
		static const std::string oid = GetDecentEnclaveOid() + '\x06';

		return oid;
	}


	static const std::string& GetPlatformIdOid()
	{
		static const std::string oid = GetDecentEnclaveOid() + '\x07';

		return oid;
	}


	//==========
	// Root.3.* - For platform specific data
	//==========


	static const std::string& GetSgxDataRootOid()
	{
		static const std::string oid = GetEnclaveTypeSpecRootOid() + '\x01';

		return oid;
	}


	//==========
	// Root.3.1.* - For SGX EPID platform data
	//==========


	static const std::string& GetSgxStdReportDataOid()
	{
		static const std::string oid = GetSgxDataRootOid() + '\x01';

		return oid;
	}


	static const std::string& GetSgxSelfRaReportOid()
	{
		static const std::string oid = GetSgxDataRootOid() + '\x02';

		return oid;
	}


}; // struct DecentOid

} // namespace Common
} // namespace DecentEnclave

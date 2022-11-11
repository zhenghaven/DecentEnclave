// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


// TODO: #ifdef DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED


#include <iterator>
#include <string>
#include <vector>

#include <cppcodec/hex_lower.hpp>
#include <curl/curl.h>
#include <sgx_report.h>

#include "../../Common/Exceptions.hpp"
#include "../../Common/Sgx/IasRequester.hpp"


namespace DecentEnclave
{
namespace Untrusted
{
namespace Sgx
{


class IasRequesterImpl :
	public Common::Sgx::IasRequester
{
public: // static members:

	using Base = Common::Sgx::IasRequester;

	using Base::GetIasUrlDev;
	using Base::GetIasUrlProd;
	using Base::GetIasSigrlUri;
	using Base::GetIasReportUri;

	using Base::GetHdrLabelSubKey;
	using Base::GetHdrLabelReqId;
	using Base::GetHdrLabelSign;
	using Base::GetHdrLabelCert;

	using Base::ParseSpid;


	using CUrlContentCallBack =
		std::function<size_t(char*, size_t, size_t, void*)>;
	using CUrlHeaderCallBack =
		std::function<size_t(char*, size_t, size_t, void*)>;

public:

	IasRequesterImpl(
		const std::string& iasUrl,
		const std::string& subscriptionKey
	) :
		Base(),
		m_iasUrl(iasUrl),
		m_subscriptionKey(subscriptionKey)
	{}

	virtual ~IasRequesterImpl() = default;


	virtual std::string GetSigrl(const sgx_epid_group_id_t& gid) const override
	{
		std::string reqFullUrl = m_iasUrl + GetIasSigrlUri();

		std::string gidStr = EncodeGroupId(gid);
		reqFullUrl += gidStr;

		std::string requestId;
		CUrlHeaderCallBack headerCallback =
			[&requestId]
			(char* ptr, size_t size, size_t nitems, void*) -> size_t
			{
				static std::string tmp;
				tmp = std::string(ptr, size * nitems);
				if (tmp.find(GetHdrLabelReqId()) == 0)
				{
					requestId = ParseHeaderLine(tmp);
				}

				// If returned amount differs from the amount passed in,
				// it will signal an error to the library and cause the transfer
				// to get aborted
				// - https://curl.se/libcurl/c/CURLOPT_HEADERFUNCTION.html
				return size * nitems;
			};

		std::string outRevcList;
		CUrlContentCallBack contentCallback =
			[&outRevcList]
			(char* ptr, size_t size, size_t nmemb, void*) -> size_t
			{
				outRevcList = std::string(ptr, size * nmemb);

				// If returned amount differs from the amount passed in,
				// it will signal an error to the library and cause the transfer
				// to get aborted
				// - https://curl.se/libcurl/c/CURLOPT_HEADERFUNCTION.html
				return size * nmemb;
			};

		std::string hdrSubKey = GetHdrLabelSubKey() + ": " + m_subscriptionKey;

		DoCURL(
			reqFullUrl,
			"GET",
			{
				"Cache-Control: no-cache",
				hdrSubKey,
			},
			std::string(),
			headerCallback,
			contentCallback
		);

		return outRevcList;
	}


	virtual Common::Sgx::IasReportSet GetReport(
		const std::string& reqBody
	) const override
	{
		std::string reqFullUrl = m_iasUrl + GetIasReportUri();


		std::string requestId;
		std::string iasSign;
		std::string iasCert;
		CUrlHeaderCallBack headerCallback =
			[&requestId, &iasSign, &iasCert]
			(char* ptr, size_t size, size_t nitems, void*) -> size_t
			{
				static std::string tmp;
				tmp = std::string(ptr, size * nitems);
				if (tmp.find(GetHdrLabelReqId()) == 0)
				{
					requestId = ParseHeaderLine(tmp);
				}
				else if (tmp.find(GetHdrLabelSign()) == 0)
				{
					iasSign = ParseHeaderLine(tmp);
				}
				else if (tmp.find(GetHdrLabelCert()) == 0)
				{
					iasCert = ParseHeaderLine(tmp);
					UrlUnescape(iasCert);
				}

				// If returned amount differs from the amount passed in,
				// it will signal an error to the library and cause the transfer
				// to get aborted
				// - https://curl.se/libcurl/c/CURLOPT_HEADERFUNCTION.html
				return size * nitems;
			};

		std::string respBody;
		CUrlContentCallBack contentCallback =
			[&respBody]
			(char* ptr, size_t size, size_t nmemb, void*) -> size_t
			{
				respBody = std::string(ptr, size * nmemb);

				// If returned amount differs from the amount passed in,
				// it will signal an error to the library and cause the transfer
				// to get aborted
				// - https://curl.se/libcurl/c/CURLOPT_HEADERFUNCTION.html
				return size * nmemb;
			};

		std::string hdrSubKey = GetHdrLabelSubKey() + ": " + m_subscriptionKey;

		DoCURL(
			reqFullUrl,
			"POST",
			{
				"Cache-Control: no-cache",
				"Content-Type: application/json",
				hdrSubKey,
			},
			reqBody,
			headerCallback,
			contentCallback
		);

		Common::Sgx::IasReportSet reportSet;
		reportSet.get_Report() = respBody;
		reportSet.get_ReportSign() = iasSign;
		reportSet.get_IasCert() = iasCert;

		return reportSet;
	}

private:

	static size_t HeaderCallback(
		char *ptr,
		size_t size,
		size_t nitems,
		void *userdata
	)
	{
		if (userdata == nullptr)
		{
			return 0;
		}
		CUrlHeaderCallBack& callbackFunc =
			*static_cast<CUrlHeaderCallBack*>(userdata);
		return callbackFunc(ptr, size, nitems, nullptr);
	}

	static size_t ContentCallback(
		char *ptr,
		size_t size,
		size_t nmemb,
		void *userdata
	)
	{
		if (userdata == nullptr)
		{
			return 0;
		}
		CUrlContentCallBack& callbackFunc =
			*static_cast<CUrlContentCallBack*>(userdata);
		return callbackFunc(ptr, size, nmemb, nullptr);
	}

	static void DoCURL(
		const std::string& url,
		const std::string& method,
		const std::vector<std::string>& headerStrs,
		const std::string& body,
		CUrlHeaderCallBack& headerCallback,
		CUrlContentCallBack& contentCallback
	)
	{
		// Initialize curl
		CURL *hnd = curl_easy_init();
		if (hnd == nullptr)
		{
			throw Common::Exception("Failed to initialize curl");
		}

		// Initialize curl headers
		curl_slist* headers = nullptr;
		for (const auto& headerStr : headerStrs)
		{
			curl_slist* tmp = curl_slist_append(headers, headerStr.c_str());
			if (tmp == nullptr)
			{
				curl_slist_free_all(headers);
				curl_easy_cleanup(hnd);
				throw Common::Exception("Failed to initialize curl headers");
			}
			headers = tmp;
		}

		// Set curl options
		if (
			// curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L)
			//	!= CURLE_OK || // Turn this on for debugging
			curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, method.c_str())
				!= CURLE_OK ||
			curl_easy_setopt(hnd, CURLOPT_URL, url.c_str())
				!= CURLE_OK ||
			curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L)
				!= CURLE_OK ||
			curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L)
				!= CURLE_OK ||
			curl_easy_setopt(hnd, CURLOPT_HEADERFUNCTION, &HeaderCallback)
				!= CURLE_OK ||
			curl_easy_setopt(hnd, CURLOPT_HEADERDATA, &headerCallback)
				!= CURLE_OK ||
			curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, &ContentCallback)
				!= CURLE_OK ||
			curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &contentCallback)
				!= CURLE_OK ||
			curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers)
				!= CURLE_OK
		)
		{
			curl_slist_free_all(headers);
			curl_easy_cleanup(hnd);
			throw Common::Exception("Failed to set curl options");
		}

		if (body.size() > 0)
		{
			if (
				curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, body.c_str())
					!= CURLE_OK ||
				curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE, body.size())
					!= CURLE_OK
			)
			{
				curl_slist_free_all(headers);
				curl_easy_cleanup(hnd);
				throw Common::Exception("Failed to set curl request body");
			}
		}

		long response_code = 0;
		if (
			curl_easy_perform(hnd) != CURLE_OK ||
			curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &response_code)
				!= CURLE_OK
		)
		{
			curl_slist_free_all(headers);
			curl_easy_cleanup(hnd);
			throw Common::Exception("Failed to perform curl request");
		}

		curl_slist_free_all(headers);
		curl_easy_cleanup(hnd);
		if (response_code != 200)
		{
			throw Common::Exception(
				"Failed to get IAS SigRL (response code=" +
				std::to_string(response_code) + ")"
			);
		}
	}

	static std::string EncodeGroupId(const sgx_epid_group_id_t& gid)
	{
		std::vector<uint8_t> gidLitEnd(std::begin(gid), std::end(gid));
		std::vector<uint8_t> gidBigEnd(gidLitEnd.rbegin(), gidLitEnd.rend());
		return cppcodec::hex_lower::encode(gidBigEnd);
	}

	// trim from start (in place)
	static std::string& Ltrim(std::string &s)
	{
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](char ch)
		{
			return !std::isspace(ch);
		}));

		return s;
	}

	// trim from end (in place)
	static std::string& Rtrim(std::string &s)
	{
		s.erase(std::find_if(s.rbegin(), s.rend(), [](char ch)
		{
			return !std::isspace(ch);
		}).base(), s.end());

		return s;
	}

	static std::string& ParseHeaderLine(std::string& s)
	{
		s = s.substr(s.find_first_of(':') + 1);
		Rtrim(Ltrim(s));
		return s;
	}

	static void UrlUnescape(std::string& s)
	{
		int outLen = 0;
		char* resStr = curl_easy_unescape(
			nullptr, // Since curl 7.82.0, this parameter is ignored
			s.c_str(),
			s.size(),
			&outLen
		);
		if (resStr == nullptr)
		{
			throw Common::Exception("Failed to do URL unescape");
		}
		std::copy(resStr, resStr + outLen, s.begin());
		curl_free(resStr);
		s.resize(outLen);
	}

	std::string m_iasUrl;
	std::string m_subscriptionKey;

}; // class IasRequesterImpl


} // namespace Sgx
} // namespace Untrusted
} // namespace DecentEnclave

// TODO: #endif // DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED

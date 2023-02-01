// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <memory>
#include <unordered_map>

#include <SimpleSysIO/StreamSocketBase.hpp>

#include "../../Common/Exceptions.hpp"
#include "../../Common/Internal/SimpleSysIO.hpp"
#include "../../Common/Platform/Print.hpp"
#include "../Config/EndpointsMgr.hpp"
#include "DecentLambdaFunc.hpp"

namespace DecentEnclave
{
namespace Untrusted
{
namespace Hosting
{


class LambdaFuncServer
{
public: // static members:

	using SocketType = Common::Internal::SysIO::StreamSocketBase;
	using AcceptorType = Common::Internal::SysIO::StreamAcceptorBase;

	using ServerBinding = std::pair<
		std::shared_ptr<DecentLambdaFunc>,
		std::shared_ptr<AcceptorType>
	>;

public:

	LambdaFuncServer(std::shared_ptr<Config::EndpointsMgr> endpointsMgr) :
		m_endpointsMgr(std::move(endpointsMgr)),
		m_funcMap()
	{}


	~LambdaFuncServer() = default;


	void AddFunction(
		const std::string& name,
		std::shared_ptr<DecentLambdaFunc> func
	)
	{
		if (m_funcMap.find(name) != m_funcMap.end())
		{
			throw Common::Exception("Function name already exists.");
		}

		std::shared_ptr<AcceptorType> acceptor =
			m_endpointsMgr->GetStreamAcceptor(name);

		auto res = m_funcMap.emplace(
			name,
			std::make_pair(std::move(func), std::move(acceptor))
		);

		StartAccepting(
			res.first->second.first,
			res.first->second.second
		);
	}


private: // static members:

	static void StartAccepting(
		std::shared_ptr<DecentLambdaFunc> func,
		std::shared_ptr<AcceptorType> acceptor
	)
	{
		auto callback =
			[func, acceptor](
				std::unique_ptr<SocketType> sock,
				bool hasErrorOccurred
			)
			{
				if (!hasErrorOccurred)
				{
					// no error occurred

					// log new connection
					Common::Platform::Print::StrInfo(
						"LambdaFuncServer - New connection accepted"
					);

					// Repeat to accept new connection
					StartAccepting(func, acceptor);

					// proceed to handle the call
					func->HandleCall(std::move(sock));
				}
			};


		Common::Platform::Print::StrDebug(
			"LambdaFuncServer - Listening for incoming connection..."
		);
		acceptor->AsyncAccept(std::move(callback));
	}

private:

	std::shared_ptr<Config::EndpointsMgr> m_endpointsMgr;

	std::unordered_map<std::string, ServerBinding> m_funcMap;

}; // class LambdaFuncServer


} // namespace Hosting
} // namespace Untrusted
} // namespace DecentEnclave

// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <SimpleObjects/SimpleObjects.hpp>
#include <SimpleSysIO/SysCall/TCPAcceptor.hpp>
#include <SimpleSysIO/SysCall/TCPSocket.hpp>

#include "../../Common/Internal/SimpleObj.hpp"
#include "../../Common/Internal/SimpleSysIO.hpp"
#include "../../Common/Exceptions.hpp"


namespace DecentEnclave
{
namespace Untrusted
{
namespace Config
{

class Endpoint
{
public: // static members:

	using StreamAcceptorType = Common::Internal::SysIO::StreamAcceptorBase;
	using StreamSocketType   = Common::Internal::SysIO::StreamSocketBase;

public:
	Endpoint() = default;

	// LCOV_EXCL_START
	virtual ~Endpoint() = default;
	// LCOV_EXCL_STOP

	virtual std::unique_ptr<StreamAcceptorType> GetStreamAcceptor() const = 0;

	virtual std::unique_ptr<StreamSocketType> GetStreamSocket() const = 0;

}; // class Endpoint

class EndpointIP : public Endpoint
{
public:
	EndpointIP(const std::string& ip, const uint16_t port) :
		m_ip(ip),
		m_port(port)
	{}

	virtual
	std::unique_ptr<StreamAcceptorType>
	GetStreamAcceptor() const override
	{
		using namespace Common::Internal::SysIO;
		return SysCall::TCPAcceptor::BindV4(m_ip, m_port);
	}

	virtual
	std::unique_ptr<StreamSocketType>
	GetStreamSocket() const override
	{
		using namespace Common::Internal::SysIO;
		return SysCall::TCPSocket::ConnectV4(m_ip, m_port);
	}

private:

	std::string m_ip;
	uint16_t m_port;
}; // struct EndpointIP


class EndpointsMgr
{
public: // static members:

	using StreamAcceptorType = Common::Internal::SysIO::StreamAcceptorBase;
	using StreamSocketType   = Common::Internal::SysIO::StreamSocketBase;

public: // static members:

	using EndpointList =
		std::unordered_map<std::string, std::unique_ptr<Endpoint> >;
	using EndpointsMap =
		std::unordered_map<std::string, EndpointList>;


	static std::shared_ptr<EndpointsMgr> GetInstancePtr(
		const Common::Internal::Obj::Object* config = nullptr
	)
	{
		static std::shared_ptr<EndpointsMgr> s_instPtr =
			std::make_shared<EndpointsMgr>(*config);

		return s_instPtr;
	}

	static const EndpointsMgr& GetInstance()
	{
		static const EndpointsMgr& s_instRef = *GetInstancePtr();

		return s_instRef;
	}


public:
	EndpointsMgr(const Common::Internal::Obj::Object& config) :
		m_inEndpoints(),
		m_outEndpoints()
	{
		using namespace Common::Internal::Obj;

		const auto& cmpMap =
			config.AsDict()[String("AuthorizedComponents")].AsDict();
		for (const auto& pair : cmpMap)
		{
			const auto& cmpName = std::get<0>(pair)->AsString();

			std::string cmpNameStr(cmpName.c_str(), cmpName.size());
			auto& endpointListIn  = m_inEndpoints[cmpNameStr];
			auto& endpointListOut = m_inEndpoints[cmpNameStr];

			const auto& cmpInfo = std::get<1>(pair)->AsDict();
			const auto& endpointMap = cmpInfo[String("Endpoints")].AsDict();
			for (const auto& endpointPair : endpointMap)
			{
				const auto& endpointName = std::get<0>(endpointPair)->AsString();
				const auto& endpointInfo = std::get<1>(endpointPair)->AsDict();

				const auto& ip = endpointInfo[String("IP")].AsString();
				uint32_t port = endpointInfo[String("Port")].AsCppUInt32();
				bool incoming = endpointInfo[String("Incoming")].IsTrue();

				if (incoming)
				{
					endpointListIn.emplace(
						std::string(endpointName.c_str(), endpointName.size()),
						Internal::make_unique<EndpointIP>(
							std::string(ip.c_str(), ip.size()),
							static_cast<uint16_t>(port)
						)
					);
				}
				else
				{
					endpointListOut.emplace(
						std::string(endpointName.c_str(), endpointName.size()),
						Internal::make_unique<EndpointIP>(
							std::string(ip.c_str(), ip.size()),
							static_cast<uint16_t>(port)
						)
					);
				}
			}
		}
	}


	std::unique_ptr<StreamAcceptorType>
	GetStreamAcceptor(const std::string& componentName) const
	{
		return PickAnyEndpointWithName(
			m_inEndpoints,
			componentName
		).GetStreamAcceptor();
	}


	std::unique_ptr<StreamSocketType>
	GetStreamSocket(const std::string& componentName) const
	{
		return PickAnyEndpointWithName(
			m_outEndpoints,
			componentName
		).GetStreamSocket();
	}


private: // static members:

	static const Endpoint& PickAnyEndpointWithName(
		const EndpointsMap& endpointsMap,
		const std::string& componentName
	)
	{
		const auto& endpointList = endpointsMap.find(componentName);
		if (
			endpointList == endpointsMap.end() ||
			endpointList->second.empty()
		)
		{
			throw Common::Exception(
				"EndpointMgr::PickAnyEndpointWithName - "
				"Component named " + componentName + " not found."
			);
		}

		return *(endpointList->second.begin()->second);
	}

private:

	EndpointsMap m_inEndpoints;
	EndpointsMap m_outEndpoints;
}; // class EndpointsMgr


} // namespace Config
} // namespace Untrusted
} // namespace DecentEnclave

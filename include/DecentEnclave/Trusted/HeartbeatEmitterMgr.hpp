// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <functional>
#include <mutex>
#include <vector>

#include "../Common/Platform/Print.hpp"


namespace DecentEnclave
{
namespace Trusted
{


class HeartbeatEmitterMgr
{
public: // static members:

	using EmitterFunc = std::function<void()>;
	using EmitterListType = std::vector<EmitterFunc>;

	static HeartbeatEmitterMgr& GetInstance()
	{
		static HeartbeatEmitterMgr inst;
		return inst;
	}

public:

	HeartbeatEmitterMgr() :
		m_emitterListMutex(),
		m_emitterList()
	{}

	~HeartbeatEmitterMgr() = default;


	void AddEmitter(EmitterFunc emitter)
	{
		std::lock_guard<std::mutex> lock(m_emitterListMutex);
		m_emitterList.emplace_back(std::move(emitter));
	}

	void EmitAll() const
	{
		Common::Platform::Print::StrDebug("Emitting heartbeat...");

		std::vector<std::reference_wrapper<const EmitterFunc> > emitterRefList;
		{
			std::lock_guard<std::mutex> lock(m_emitterListMutex);
			emitterRefList.reserve(m_emitterList.size());
			for (const auto& emitter : m_emitterList)
			{
				emitterRefList.emplace_back(emitter);
			}
		}

		for (const EmitterFunc& emitter : emitterRefList)
		{
			emitter();
		}
	}

private:

	mutable std::mutex m_emitterListMutex;
	EmitterListType m_emitterList;

}; // class HeartbeatEmitterMgr


} // namespace Trusted
} // namespace DecentEnclave

// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <vector>

#include "EnclaveBase.hpp"


namespace DecentEnclave
{
namespace Untrusted
{


class DecentEnclaveBase : virtual public EnclaveBase
{
public:
	DecentEnclaveBase() = default;

	// LCOV_EXCL_START
	virtual ~DecentEnclaveBase() = default;
	// LCOV_EXCL_STOP

	// TODO: deterministic message interface
	// virtual void HandleMsg(
	// const std::vector<uint8_t>& eventId,
	// const std::vector<uint8_t>& content,
	// const std::vector<uint8_t>& signature,
	// std::unique_ptr<Connection> connection
	// ) = 0;

}; // class DecentEnclaveBase


} // namespace Untrusted
} // namespace DecentEnclave

// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <memory>

#include "../Common/AuthList.hpp"


namespace DecentEnclave
{
namespace Trusted
{


const Common::AuthList& GetAuthList(
	Common::AuthList* authListPtr = nullptr
)
{
	static Common::AuthList s_authList = std::move(*authListPtr);

	return s_authList;
}


} // namespace Trusted
} // namespace DecentEnclave

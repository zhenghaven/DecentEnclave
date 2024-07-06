// Copyright (c) 2024 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <SimpleJson/SimpleJson.hpp>


namespace DecentEnclave
{
namespace Common
{
namespace Internal
{


#ifdef SIMPLEJSON_CUSTOMIZED_NAMESPACE
namespace Json = ::SIMPLEJSON_CUSTOMIZED_NAMESPACE;
#else
namespace Json = ::SimpleJson;
#endif // SIMPLEJSON_CUSTOMIZED_NAMESPACE


} // namespace Internal
} // namespace Common
} // namespace DecentEnclave


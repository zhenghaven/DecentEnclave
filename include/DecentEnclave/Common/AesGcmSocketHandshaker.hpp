// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstdint>

#include <vector>

#include <mbedTLScpp/SKey.hpp>
#include <SimpleSysIO/StreamSocketBase.hpp>


namespace DecentEnclave
{
namespace Common
{


class AesGcmSocketHandshaker
{
public:

	AesGcmSocketHandshaker() = default;
	// LCOV_EXCL_START
	virtual ~AesGcmSocketHandshaker() = default;
	// LCOV_EXCL_STOP


	virtual mbedTLScpp::SKey<128> GetSecretKey128() const = 0;
	virtual mbedTLScpp::SKey<128> GetMaskKey128() const = 0;


	virtual bool IsHandshakeDone() const = 0;


	virtual void HandshakeStep(SimpleSysIO::StreamSocketBase& sock) = 0;
	virtual void Handshake(SimpleSysIO::StreamSocketBase& sock)
	{
		while (!IsHandshakeDone())
		{
			HandshakeStep(sock);
		}
	}

}; // class AesGcmSocketHandshaker


} // namespace Common
} // namespace DecentEnclave

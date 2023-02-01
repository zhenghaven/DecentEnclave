// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstddef>
#include <cstdint>

#include <limits>
#include <memory>
#include <vector>

#include <mbedTLScpp/Hkdf.hpp>
#include <mbedTLScpp/SecretVector.hpp>
#include <SimpleObjects/Internal/make_unique.hpp>
#include <SimpleSysIO/StreamSocketBase.hpp>

#include "Internal/SimpleObj.hpp"
#include "Internal/SimpleSysIO.hpp"
#include "Platform/AesGcm.hpp"
#include "AesGcmPackager.hpp"
#include "AesGcmSocketHandshaker.hpp"


namespace DecentEnclave
{
namespace Common
{


template<size_t _keyBitSize>
class AesGcmStreamSocket:
	public Internal::SysIO::StreamSocketBase
{
public: //static members:

	using Base = Internal::SysIO::StreamSocketBase;
	using SocketType = Internal::SysIO::StreamSocketBase;

	using PlatformAesGcm = Platform::AesGcmOneGoNative<_keyBitSize>;
	using HandshakerType = AesGcmSocketHandshaker<_keyBitSize>;
	using CryptoPackager = AesGcmPackager<PlatformAesGcm>;

	using KeyType = typename HandshakerType::RetKeyType;

	using SizedSendSizeType = uint64_t;

	static constexpr size_t sk_keyBitSize = _keyBitSize;
	static constexpr size_t sk_keyByteSize = sk_keyBitSize / 8;
	static constexpr uint64_t sk_maxCounter =
		std::numeric_limits<uint64_t>::max();
	static constexpr size_t sk_packBlockSize = 128;

	static const std::string& GetSecKeyDerLabel()
	{
		static const std::string s_label = "next_secret_key";
		return s_label;
	}

	static const std::string& GetMakKeyDerLabel()
	{
		static const std::string s_label = "next_maskin_key";
		return s_label;
	}


private: // static members:

	class AsyncRecvHandler:
		public std::enable_shared_from_this<AsyncRecvHandler>
	{
	public: // static members:

		using EnableSharedFromThis =
			std::enable_shared_from_this<AsyncRecvHandler>;

	public:
		static std::shared_ptr<AsyncRecvHandler> Create(
			StreamSocketBase* sock,
			typename Base::AsyncRecvCallback callback
		)
		{
			return std::shared_ptr<AsyncRecvHandler>(
				new AsyncRecvHandler(sock, std::move(callback))
			);
		}

		static void InitAsyncRecv(
			std::shared_ptr<AsyncRecvHandler> handler
		)
		{
			size_t sizeExpecting = sizeof(SizedSendSizeType) - (handler->m_recvdSize);

			handler->m_sock->AsyncRecvRaw(
				sizeExpecting,
				[handler](std::vector<uint8_t> data, bool hasErrorOccurred)
				{
					handler->PackSizeRecvHandler(
						std::move(data),
						hasErrorOccurred
					);
				}
			);
		}

		static void PackAsyncRecv(
			std::shared_ptr<AsyncRecvHandler> handler
		)
		{
			size_t sizeExpecting = (handler->m_packSize) - (handler->m_recvdSize);
			handler->m_sock->AsyncRecvRaw(
				sizeExpecting,
				[handler](std::vector<uint8_t> data, bool hasErrorOccurred)
				{
					handler->PackRecvHandler(
						std::move(data),
						hasErrorOccurred
					);
				}
			);
		}

		void PackSizeRecvHandler(
			std::vector<uint8_t> data,
			bool hasErrorOccurred
		)
		{
			if (!hasErrorOccurred)
			{
				std::memcpy(
					reinterpret_cast<uint8_t*>(&m_packSize) + m_recvdSize,
					data.data(),
					data.size()
				);
				m_recvdSize += data.size();

				if (m_recvdSize < sizeof(SizedSendSizeType))
				{
					InitAsyncRecv(GetSharedPtr());
				}
				else
				{
					m_recvdSize = 0; // clear the counter
					m_recvBuf.resize(m_packSize); // resize the buffer
					PackAsyncRecv(GetSharedPtr());
				}
			}
		}

		void PackRecvHandler(
			std::vector<uint8_t> data,
			bool hasErrorOccurred
		)
		{
			if (!hasErrorOccurred)
			{
				std::memcpy(
					m_recvBuf.data() + m_recvdSize,
					data.data(),
					data.size()
				);
				m_recvdSize += data.size();

				if (m_recvdSize < m_packSize)
				{
					PackAsyncRecv(GetSharedPtr());
				}
				else
				{
					// We have received the whole package
					m_callback(
						std::move(m_recvBuf),
						false
					);
				}
			}
		}

	private:

		AsyncRecvHandler(
			Base* sock,
			typename Base::AsyncRecvCallback callback
		) :
			m_sock(sock),
			m_packSize(0),
			m_recvdSize(0),
			m_recvBuf(),
			m_callback(std::move(callback))
		{}

		std::shared_ptr<AsyncRecvHandler> GetSharedPtr()
		{
			return EnableSharedFromThis::shared_from_this();
		}

		Base* m_sock;
		SizedSendSizeType m_packSize;
		size_t m_recvdSize;
		std::vector<uint8_t> m_recvBuf;
		typename Base::AsyncRecvCallback m_callback;
	}; // class AsyncRecvHandler


public:

	AesGcmStreamSocket() = delete;


	AesGcmStreamSocket(
		std::unique_ptr<HandshakerType> handshaker,
		std::unique_ptr<StreamSocketBase> sock
	) :
		m_handshaker(std::move(handshaker)),
		m_selfSecKey(),
		m_selfMakKey(),
		m_selfAddData(),
		m_selfAesGcm(),
		m_peerSecKey(),
		m_peerMakKey(),
		m_peerAddData(),
		m_peerAesGcm(),
		m_socket(std::move(sock)),
		m_recvBuf()
	{
		// perform handshake
		m_handshaker->Handshake(*m_socket);

		// set self keys
		m_selfSecKey = m_handshaker->GetSecretKey();
		m_selfMakKey = m_handshaker->GetMaskKey();

		// set peer keys
		m_peerSecKey = m_handshaker->GetSecretKey();
		m_peerMakKey = m_handshaker->GetMaskKey();

		RefreshSelfAddData();
		RefreshPeerAddData();
	}


	//Copy is prohibited.
	AesGcmStreamSocket(const AesGcmStreamSocket& other) = delete;

	/**
	 * \brief	Move constructor
	 *
	 * \param [in,out]	other	The other.
	 */
	AesGcmStreamSocket(AesGcmStreamSocket&& other) :
		m_handshaker(std::move(other.m_handshaker)),
		m_selfSecKey(std::move(other.m_selfSecKey)),
		m_selfMakKey(std::move(other.m_selfMakKey)),
		m_selfAddData(std::move(other.m_selfAddData)),
		m_selfAesGcm(std::move(other.m_selfAesGcm)),
		m_peerSecKey(std::move(other.m_peerSecKey)),
		m_peerMakKey(std::move(other.m_peerMakKey)),
		m_peerAddData(std::move(other.m_peerAddData)),
		m_peerAesGcm(std::move(other.m_peerAesGcm)),
		m_socket(std::move(other.m_socket)),
		m_recvBuf(std::move(other.m_recvBuf))
	{}


	// LCOV_EXCL_START
	/** \brief	Destructor */
	virtual ~AesGcmStreamSocket() = default;
	// LCOV_EXCL_STOP


	//Copy is prohibited.
	AesGcmStreamSocket& operator=(const AesGcmStreamSocket& other) = delete;


	/**
	 * \brief	Move assignment operator
	 *
	 * \exception Decent::Net::Exception
	 *
	 * \param [in,out]	other	The other.
	 *
	 * \return	A reference to this object.
	 */
	AesGcmStreamSocket& operator=(AesGcmStreamSocket&& other)
	{
		if (this != &other)
		{
			m_handshaker = std::move(other.m_handshaker);
			m_selfSecKey = std::move(other.m_selfSecKey);
			m_selfMakKey = std::move(other.m_selfMakKey);
			m_selfAddData = std::move(other.m_selfAddData);
			m_selfAesGcm = std::move(other.m_selfAesGcm);
			m_peerSecKey = std::move(other.m_peerSecKey);
			m_peerMakKey = std::move(other.m_peerMakKey);
			m_peerAddData = std::move(other.m_peerAddData);
			m_peerAesGcm = std::move(other.m_peerAesGcm);
			m_socket = std::move(other.m_socket);
			m_recvBuf = std::move(other.m_recvBuf);
		}

		return *this;
	}


	virtual size_t SendRaw(const void* buf, const size_t size) override
	{
		std::vector<uint8_t> encBlock = EncryptMsg(
			std::vector<uint8_t>(
				static_cast<const uint8_t*>(buf),
				static_cast<const uint8_t*>(buf) + size
			)
		);

		m_socket->SizedSendBytes<std::vector<uint8_t>, SizedSendSizeType>(
			encBlock
		);

		return size;
	}


	virtual size_t RecvRaw(void* buf, const size_t size) override
	{
		if (m_recvBuf.size() == 0)
		{
			//Buffer is clear, we need to poll data from remote first.

			std::vector<uint8_t> encBlock =
				m_socket->SizedRecvBytes<
					std::vector<uint8_t>,
					SizedSendSizeType
				>();

			m_recvBuf = DecryptMsg(encBlock);
		}

		const bool isOutBufEnough = m_recvBuf.size() <= size;
		const size_t byteToCopy = isOutBufEnough ? m_recvBuf.size() : size;

		std::memcpy(buf, m_recvBuf.data(), byteToCopy);

		//Clean the buffer
		if (isOutBufEnough)
		{
			m_recvBuf.clear();
		}
		else
		{
			m_recvBuf.erase(
				m_recvBuf.begin(),
				m_recvBuf.begin() + byteToCopy
			);
		}

		return byteToCopy;
	}

	virtual void AsyncRecvRaw(
		size_t buffSize,
		typename Base::AsyncRecvCallback callback
	) override
	{
		if (m_recvBuf.size() > 0)
		{
			// the recv buffer is not empty
			// we can use them first
			callback(
				std::vector<uint8_t>(
					m_recvBuf.data(),
					m_recvBuf.data() + m_recvBuf.size()
				),
				false
			);
			m_recvBuf.clear();
		}
		else
		{
			// the recv buffer is empty
			// we need to poll data from remote

			auto handler = AsyncRecvHandler::Create(
				m_socket.get(),
				[this, callback](
					std::vector<uint8_t> data,
					bool hasErrorOccurred
				)
				{
					if (!hasErrorOccurred)
					{
						auto decMsg = DecryptMsg(data);
						callback(
							std::vector<uint8_t>(
								decMsg.data(),
								decMsg.data() + decMsg.size()
							),
							false
						);
					}
				}
			);
			AsyncRecvHandler::InitAsyncRecv(handler);
		}
	}


protected:

	/**
	 * \brief	Decrypts a message into binary
	 *
	 * \param 	inMsg	Input message (cipher text).
	 *
	 * \return	Output message in binary (plain text).
	 */
	virtual
	mbedTLScpp::SecretVector<uint8_t> DecryptMsg(
		const std::vector<uint8_t>& inMsg
	)
	{
		mbedTLScpp::SecretVector<uint8_t> res;
		std::tie(res, std::ignore) = m_peerAesGcm->Unpack(
			mbedTLScpp::CtnFullR(inMsg),
			mbedTLScpp::CtnFullR(m_peerAddData),
			nullptr
		);

		CheckPeerKeysLifetime();

		return res;
	}

	/**
	 * \brief	Encrypts a message into binary
	 *
	 * \exception Decent::Net::Exception
	 *
	 * \param 	inMsg	Input message (plain text).
	 *
	 * \return	Output message in binary (cipher text).
	 */
	virtual
	std::vector<uint8_t> EncryptMsg(
		const std::vector<uint8_t>& inMsg
	)
	{
		std::vector<uint8_t> res;
		std::tie(res, std::ignore) = m_selfAesGcm->Pack(
			mbedTLScpp::CtnFullR(mbedTLScpp::gsk_emptyCtn),
			mbedTLScpp::CtnFullR(mbedTLScpp::gsk_emptyCtn),
			mbedTLScpp::CtnFullR(inMsg),
			mbedTLScpp::CtnFullR(m_selfAddData)
		);

		CheckSelfKeysLifetime();

		return res;
	}

	virtual void CheckSelfKeysLifetime()
	{
		if (m_selfAddData[2] >= sk_maxCounter)
		{
			RefreshSelfKeys();
		}
		else
		{
			++m_selfAddData[2];
		}
	}

	virtual void CheckPeerKeysLifetime()
	{
		if (m_peerAddData[2] >= sk_maxCounter)
		{
			RefreshPeerKeys();
		}
		else
		{
			++m_peerAddData[2];
		}
	}

	virtual void RefreshSelfKeys()
	{
		KeyType tmpSecKey = mbedTLScpp::Hkdf<
			mbedTLScpp::HashType::SHA256,
			sk_keyBitSize
		>(
			mbedTLScpp::CtnFullR(m_selfSecKey),
			mbedTLScpp::CtnFullR(GetSecKeyDerLabel()),
			mbedTLScpp::CtnFullR(mbedTLScpp::gsk_emptyCtn)
		);
		KeyType tmpMakKey = mbedTLScpp::Hkdf<
			mbedTLScpp::HashType::SHA256,
			sk_keyBitSize
		>(
			mbedTLScpp::CtnFullR(m_selfMakKey),
			mbedTLScpp::CtnFullR(GetMakKeyDerLabel()),
			mbedTLScpp::CtnFullR(mbedTLScpp::gsk_emptyCtn)
		);

		m_selfSecKey = tmpSecKey;
		m_selfMakKey = tmpMakKey;

		m_selfAesGcm =
			Common::Internal::Obj::Internal::make_unique<CryptoPackager>(
				m_selfSecKey,
				sk_packBlockSize
			);

		RefreshSelfAddData();
	}

	virtual void RefreshPeerKeys()
	{
		KeyType tmpSecKey = mbedTLScpp::Hkdf<
			mbedTLScpp::HashType::SHA256,
			sk_keyBitSize
		>(
			mbedTLScpp::CtnFullR(m_peerSecKey),
			mbedTLScpp::CtnFullR(GetSecKeyDerLabel()),
			mbedTLScpp::CtnFullR(mbedTLScpp::gsk_emptyCtn)
		);
		KeyType tmpMakKey = mbedTLScpp::Hkdf<
			mbedTLScpp::HashType::SHA256,
			sk_keyBitSize
		>(
			mbedTLScpp::CtnFullR(m_peerMakKey),
			mbedTLScpp::CtnFullR(GetMakKeyDerLabel()),
			mbedTLScpp::CtnFullR(mbedTLScpp::gsk_emptyCtn)
		);

		m_peerSecKey = tmpSecKey;
		m_peerMakKey = tmpMakKey;

		m_peerAesGcm =
			Common::Internal::Obj::Internal::make_unique<CryptoPackager>(
				m_peerSecKey,
				sk_packBlockSize
			);

		RefreshPeerAddData();
	}

private:

	/** \brief Refresh self add data.
	 *         USED BY THE CONSTRUCTOR, CANNOT BE VIRTUAL!
	 */
	void RefreshSelfAddData()
	{
		static_assert(
			(
				sizeof(
					decltype(m_selfAddData)::value_type) *
					decltype(m_selfAddData)::sk_itemCount
				) ==
				(
					decltype(m_selfMakKey)::sk_itemCount +
					sizeof(decltype(m_selfAddData)::value_type)
				),
			"The size of additional data doesn't match the size actually needed."
		);
		static_assert(
			decltype(m_selfAddData)::sk_itemCount == 3,
			"The length of addtional data is too small."
		);

		std::memcpy(
			m_selfAddData.data(),
			m_selfMakKey.data(),
			decltype(m_selfMakKey)::sk_itemCount
		);

		m_selfAddData[2] = 0;
	}

	/** \brief	Refresh peer add data.
	 *         USED BY THE CONSTRUCTOR, CANNOT BE VIRTUAL!
	 */
	void RefreshPeerAddData()
	{
		static_assert(
			(
				sizeof(
					decltype(m_peerAddData)::value_type) *
					decltype(m_peerAddData)::sk_itemCount
				) ==
				(
					decltype(m_peerMakKey)::sk_itemCount +
					sizeof(decltype(m_peerAddData)::value_type)
				),
			"The size of additional data doesn't match the size actually needed."
		);
		static_assert(
			decltype(m_peerAddData)::sk_itemCount == 3,
			"The length of addtional data is too small."
		);

		std::memcpy(
			m_peerAddData.data(),
			m_peerMakKey.data(),
			decltype(m_peerMakKey)::sk_itemCount
		);

		m_peerAddData[2] = 0;
	}

private:

	std::unique_ptr<HandshakerType> m_handshaker;

	KeyType m_selfSecKey; //Secret Key
	KeyType m_selfMakKey; //Masking Key
	mbedTLScpp::SecretArray<uint64_t, 3> m_selfAddData; //Additonal Data for MAC (m_selfMakKey || MsgCounter)
	std::unique_ptr<CryptoPackager> m_selfAesGcm;

	KeyType m_peerSecKey; //Secret Key
	KeyType m_peerMakKey; //Masking Key
	mbedTLScpp::SecretArray<uint64_t, 3> m_peerAddData; //Additonal Data for MAC (m_peerMakKey || MsgCounter)
	std::unique_ptr<CryptoPackager> m_peerAesGcm;

	std::unique_ptr<SocketType> m_socket;

	mbedTLScpp::SecretVector<uint8_t> m_recvBuf;
}; // class AesGcmStreamSocket


} // namespace Common
} // namespace DecentEnclave

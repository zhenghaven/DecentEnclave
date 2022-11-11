// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstdint>

#include <sgx_tcrypto.h>


#if defined(DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED) || \
	defined(DECENT_ENCLAVE_PLATFORM_SGX_UNTRUSTED)

#pragma pack(push, 1)

typedef struct _decent_ra_msg0s_t
{
	uint32_t  extended_grp_id;
} decent_ra_msg0s_t;

typedef struct _decent_ra_msg0r_t
{
	sgx_ec256_public_t  sp_pub_key;
} decent_ra_msg0r_t;

#pragma pack(pop)

#endif // DECENT_ENCLAVE_PLATFORM_SGX_TRUSTED || _UNTRUSTED

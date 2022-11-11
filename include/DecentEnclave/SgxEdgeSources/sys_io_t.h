// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#ifndef DECENT_ENCLAVE_SGX_EDGE_SOURCES_SYS_IO_T_H
#define DECENT_ENCLAVE_SGX_EDGE_SOURCES_SYS_IO_T_H

#include "sgx_edger8r.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

sgx_status_t ocall_decent_enclave_print_str(const char* str);

sgx_status_t ocall_decent_untrusted_buffer_delete(
	uint8_t data_type,
	void* ptr
);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // !DECENT_ENCLAVE_SGX_EDGE_SOURCES_SYS_IO_T_H

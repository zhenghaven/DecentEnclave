# Copyright (c) 2023 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.


include(DecentEnclaveIntelSgx)


decent_enclave_print_config_sgx()


add_executable(
	SgxCap
	Main.cpp
)
target_link_libraries(
	SgxCap
	PUBLIC IntelSGX::Untrusted::capable
)

// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <cstdio>


extern "C" void ocall_decent_enclave_print_str(const char* str)
{
	std::printf("%s", str);
}

# Copyright (c) 2023 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

cmake_minimum_required(VERSION 3.14)

project(DecentEnclave VERSION 0.0.1 LANGUAGES CXX)

OPTION(DECENTENCLAVE_UTILS "Option to build DecentEnclave utilities." OFF)

add_subdirectory(include)

set(
	DECENTENCLAVE_HOME
	${CMAKE_CURRENT_LIST_DIR}
	CACHE STRING
	"DecentEnclave home directory"
	FORCE
)

set(
	DECENTENCLAVE_INCLUDE
	${DECENTENCLAVE_HOME}/include
	CACHE STRING
	"DecentEnclave include directory"
	FORCE
)

add_library(DecentEnclave INTERFACE)

target_include_directories(DecentEnclave INTERFACE include)

if(${DECENTENCLAVE_UTILS})
	add_subdirectory(utils)
endif(${DECENTENCLAVE_UTILS})

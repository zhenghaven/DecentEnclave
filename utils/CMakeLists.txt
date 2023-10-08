# Copyright (c) 2023 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.


include(FetchContent)


## SimpleCMakeScripts
FetchContent_Declare(
	git_simplecmakescripts
	GIT_REPOSITORY https://github.com/zhenghaven/SimpleCMakeScripts.git
	GIT_TAG        dev
)
FetchContent_MakeAvailable(git_simplecmakescripts)
simplecmakescripts_enable()


add_subdirectory(SgxCap)

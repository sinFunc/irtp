############################################################################
# Copyright (c) 2010-2022 Belledonne Communications SARL.
#
# This file is part of oRTP 
# (see https://gitlab.linphone.org/BC/public/ortp).
#
############################################################################
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
############################################################################

cmake_minimum_required(VERSION 3.11) # we need CMake 3.11 for defining 'package_source' target as custom target

if (NOT CPACK_PACKAGE_NAME)
	set(CPACK_PACKAGE_NAME "ortp")
endif()

set(CPACK_SOURCE_IGNORE_FILES "./.*")

bc_make_package_source_target()

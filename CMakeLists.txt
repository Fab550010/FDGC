#[[
 * Copyright 2021 Fabrice PREMEL. All Rights Reserved.
 *
 This file is part of FDGC.

    FDGC is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FDGC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with FDGC.  If not, see <https://www.gnu.org/licenses/>.
]]



cmake_minimum_required(VERSION 3.10)

project(fdgc VERSION 0.5 DESCRIPTION "fdgc library - decode European Digital Green Certificates" LANGUAGES C)

option(ZBAR_SUPPORT "Enable ZBAR support for direct image decoding" OFF)

add_compile_options(-g)

add_library(${PROJECT_NAME} SHARED src/fdgc.c)

#configure_file(fdgc.pc.in fdgc.in @ONLY)

set_target_properties(${PROJECT_NAME} PROPERTIES 
	VERSION ${PROJECT_VERSION}
	SOVERSION 1
	PUBLIC_HEADER include/fdgc.h
	)

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE src)

target_link_libraries(${PROJECT_NAME} qcbor m z cjson crypto curl)

if (ZBAR_SUPPORT)
	add_definitions(-DZBAR_SUPPORT)
	#	add_definitions(-DMAGICKCORE_HDRI_ENABLE=0 -DMAGICKCORE_QUANTUM_DEPTH=16)
	#	include_directories(/usr/include/ImageMagick-6 /usr/include/x86_64-linux-gnu/ImageMagick-6/)
	#	target_link_libraries(${PROJECT_NAME} zbar GraphicsMagickWand)
	target_link_libraries(${PROJECT_NAME} zbar png)
endif()

#include(GNUInstallDirs)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${CMAKE_INSTALL_PREFIX}/bin)
set(libdir ${CMAKE_INSTALL_PREFIX}/lib)
set(includedir ${CMAKE_INSTALL_PREFIX}/include)
set(dist_dir ${CMAKE_BINARY_DIR})

install(TARGETS ${PROJECT_NAME}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES ${CMAKE_BINARY_DIR}/fdgc.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)

add_subdirectory(tests)




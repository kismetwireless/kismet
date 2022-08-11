# Based on the hackrf cmakefiles, in turn based on the libftdi cmake

cmake_minimum_required(VERSION 2.8)
project(libwifiuserspace C)
set(PACKAGE libwifiuserspace)
include(${PROJECT_SOURCE_DIR}/../cmake/set_release.cmake)
add_definitions(-DRELEASE="${RELEASE}")
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake/modules)

if(MSVC)
    find_package(PThread REQUIRED)
    include_directories(${PTHREAD_INCLUDE_DIR}) 
    set(INT_THREAD_LIBS ${PTHREADS_LIBRARY})

    find_package(LibUSB-1.0 REQUIRED)
    include_directories(${LIBUSB_1_INCLUDE_DIR})
    link_directories(${LIBUSB_1_LIBRARY_DIR})
    set(INT_LIBUSB_LIBS ${LIBUSB_1_LIBRARIES})

    set(sharedir "./")
    set(INSTALL_LIB_DIR "./")
    set(INSTALL_DEFAULT_BINDIR "./")
else()
    find_package(Threads REQUIRED)
    set(INT_THREAD_LIBS ${THREADS_LIBRARY})

    find_package(USB1 REQUIRED)
    include_directories(${LIBUSB_INCLUDE_DIR})
    set(INT_LIBUSB_LIBS ${LIBUSB_LIBRARIES})
    
    set (sharedir \${prefix}/share/wifiuserspace/firmware)

    set(INSTALL_LIB_DIR \${lib}suffix)

    set(INSTALL_DEFAULT_BINDIR "bin")
endif()

add_definitions(-DFIRMWAREDIR="${prefix}/share/wifiuserspace/firmware")

set(c_sources 
    ${CMAKE_CURRENT_SOURCE_DIR}/rt2800usb/rt2800lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/rt2800usb/rt2800usb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/rt2800usb/rt2x00.c
    ${CMAKE_CURRENT_SOURCE_DIR}/rt2800usb/rt2x00mac.c
    ${CMAKE_CURRENT_SOURCE_DIR}/rt2800usb/rt2x00usb.c

    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/cfg80211.c
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/crc_ccit.c

    ${CMAKE_CURRENT_SOURCE_DIR}/userspace/userspace.c

    CACHE INTERNAL "List of C sources")

set(c_kernel_headers
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/kernel.h
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/kernel/usb.h
    CACHE INTERNAL "List of userspace-kernel headers")
set(c_userspace_headers
    ${CMAKE_CURRENT_SOURCE_DIR}/userspace/userspace.h
    CACHE INTERNAL "List of userspace API eaders")

add_library(wifiuserspace SHARED ${c_sources})
set_target_properties(wifiuserspace PROPERTIES VERSION 2019.09.0 SOVERSION 0)

add_library(wifiuserspace-static STATIC ${c_sources})
if (MSVC)
    set_target_properties(wifiuserspace-static PROPERTIES OUTPUT_NAME "wifiuserspace_static")
else()
    set_target_properties(wifiuserspace-static PROPERTIES OUTPUT_NAME "wifiuserspace")
endif()

set_target_properties(wifiuserspace PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties(wifiuserspace-static PROPERTIES CLEAN_DIRECT_OUTPUT 1)

target_link_libraries(wifiuserspace ${INT_THREAD_LIBS} ${INT_LIBUSB_LIBS} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(wifiuserspace-static ${INT_THREAD_LIBS} ${INT_LIBUSB_LIBS} ${CMAKE_THREAD_LIBS_INIT})


if(INSTALL_LIBUSERSPACE)
    if(MSVC)
    # Static linkage only on win32
    else()
       install(TARGETS wifiuserspace
               LIBRARY DESTINATION ${INSTALL_LIB_DIR}
               COMPONENT sharedlibs
               )
       install(TARGETS wifiuserspace-static
               ARCHIVE DESTINATION ${INSTALL_LIB_DIR}
               COMPONENT staticlibs
               )
       install(FILES ${c_kernel_headers}
               DESTINATION include/${PROJECT_NAME}
               COMPONENT headers
               )
       install(FILES ${c_userspace_headers}
               DESTINATION include/${PROJECT_NAME}
               COMPONENT headers
               )
    endif()

    INSTALL(
        DIRECTORY ${PROJECT_SOURCE_DIR}/firmware/
        DESTINATION ${sharedir}
    )
endif(INSTALL_LIBUSERSPACE)

include_directories(${PROJECT_SOURCE_DIR})


#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

# cm_find_package(${CMAKE_WORKSPACE_NAME}_block)

if(NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
    cm_find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

cm_test_link_libraries(${Boost_LIBRARIES})
# cm_test_link_libraries(curcuit_lib ${Boost_LIBRARIES})

macro(define_test name)
    cm_test(NAME ${name}_test SOURCES ${name}.cpp)

    # target_include_directories(hash_${name}_test PRIVATE
    #                            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    #                            "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"

    #                            ${Boost_INCLUDE_DIRS})

    set_target_properties(${name}_test PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED TRUE)

    if ($ENV{TEST_TRACING})
        target_compile_definitions(${name}_test PRIVATE TEST_TRACING)
    endif()

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${name}_test PRIVATE "-fconstexpr-steps=2147483647")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${name}_test PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

    # string(CONCAT TEST_DATA ${CMAKE_CURRENT_SOURCE_DIR} "/data/" "${name}" ".json")
    # target_compile_definitions(hash_${name}_test PRIVATE TEST_DATA="${TEST_DATA}")

endmacro()

set(TESTS_NAMES
    "lib"
)

file(COPY "data/" DESTINATION "data/")

foreach(TEST_NAME ${TESTS_NAMES})
    define_test(${TEST_NAME})
endforeach()
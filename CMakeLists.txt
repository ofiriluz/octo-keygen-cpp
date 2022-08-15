CMAKE_MINIMUM_REQUIRED(VERSION 3.16)

PROJECT(octo-keygen-cpp)

# Add CMake options to path
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)
INCLUDE(ConfigOptions)
INCLUDE(LoadConanBuildInfo)
LOAD_CONAN_BUILD_INFO()

# Sources and definitions
SET(KEYGEN_SRCS
    src/keygen-options.cpp
)

SET(OPENSSL_KEYGEN_SRCS
    src/openssl/ssl-keygen.cpp
    src/openssl/ssl-keypair-certificate.cpp
    src/openssl/ssl-keypair-certificate-chain.cpp
    src/openssl/ssl-keypair.cpp
)

# Library definition
ADD_LIBRARY(octo-keygen-cpp STATIC
    ${KEYGEN_SRCS}
    ${OPENSSL_KEYGEN_SRCS}
)

# Properties
SET_TARGET_PROPERTIES(octo-keygen-cpp PROPERTIES CXX_STANDARD 17 POSITION_INDEPENDENT_CODE ON)

TARGET_INCLUDE_DIRECTORIES(octo-keygen-cpp
    PUBLIC
        # Keygen includes
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

TARGET_LINK_LIBRARIES(octo-keygen-cpp
    # Octo Libraries, all static
    octo::octo-logger-cpp
    octo::octo-encryption-cpp

    # 3rd Parties
    fmt::fmt
    openssl::ssl
    openssl::crypto
)

# Installation of the keygen library
INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
)

INSTALL(TARGETS octo-keygen-cpp
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

# Unit tests
IF(NOT DISABLE_TESTS)
    ENABLE_TESTING()
    ADD_SUBDIRECTORY(unittests)
ENDIF()

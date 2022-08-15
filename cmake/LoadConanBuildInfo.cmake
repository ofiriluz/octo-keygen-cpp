FUNCTION(load_conan_build_info)
    # Find Conan cmake definition
    FIND_FILE(CONAN_${PROJECT_NAME}_BUILD_INFO
        conanbuildinfo.cmake
        PATHS
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/build
        ${CMAKE_CURRENT_SOURCE_DIR}/../build
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/build
        ${CMAKE_SOURCE_DIR}/../build
        ${CMAKE_BINARY_DIR}
    )
    # Include Conan definition and set RPATHS
    INCLUDE(${CONAN_${PROJECT_NAME}_BUILD_INFO})
    CONAN_BASIC_SETUP(TARGETS KEEP_RPATHS)

    SET(CONAN_BUILD_INFO_FOUND TRUE PARENT_SCOPE)
    SET(LIBFMT_ROOT ${CONAN_LIBFMT_ROOT} PARENT_SCOPE)
    SET(OPENSSL_ROOT ${CONAN_OPENSSL_ROOT} PARENT_SCOPE)
    SET(OCTO_LOGGER_CPP_ROOT ${CONAN_OCTO-LOGGER-CPP_ROOT} PARENT_SCOPE)
    SET(OCTO_ENCRYPTION_CPP_ROOT ${CONAN_OCTO-ENCRYPTION-CPP_ROOT} PARENT_SCOPE)
ENDFUNCTION()
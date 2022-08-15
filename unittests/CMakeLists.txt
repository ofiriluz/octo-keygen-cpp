# Exectuable definition
ADD_EXECUTABLE(ssl-keygen-tests
    src/ssl-keygen-tests.cpp
)

# Properties
SET_TARGET_PROPERTIES(ssl-keygen-tests PROPERTIES CXX_STANDARD 17 POSITION_INDEPENDENT_CODE ON)

TARGET_LINK_LIBRARIES(ssl-keygen-tests
    # Octo Libraries, all static
    octo-keygen-cpp

    # System libraries
    $<$<PLATFORM_ID:Linux>:pthread>
)

# Test definitions
INCLUDE(CTest)
ADD_TEST(NAME ssl-keygen-tests COMMAND ssl-keygen-tests)

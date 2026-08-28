cmake_minimum_required(VERSION 3.16)
project(agentgate LANGUAGES CXX VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# No external dependencies: the build must succeed with no network access,
# which is a hard requirement of the reproducibility gate.
add_library(agentgate_core STATIC
  src/core.cpp
  src/lexer.cpp
  src/parser.cpp
  src/baseline.cpp
  src/policy.cpp
  src/stream.cpp
)
target_include_directories(agentgate_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
  target_compile_options(agentgate_core PRIVATE /W4)
else()
  target_compile_options(agentgate_core PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
endif()

add_executable(agentgate-baseline src/main_baseline.cpp)
target_link_libraries(agentgate-baseline PRIVATE agentgate_core)

add_executable(agentgate-advanced src/main_advanced.cpp)
target_link_libraries(agentgate-advanced PRIVATE agentgate_core)

enable_testing()
add_executable(agentgate_tests tests/test_agentgate.cpp)
target_link_libraries(agentgate_tests PRIVATE agentgate_core)
if(NOT MSVC)
  target_compile_options(agentgate_tests PRIVATE -Wall -Wextra)
endif()
add_test(NAME agentgate_tests COMMAND agentgate_tests)

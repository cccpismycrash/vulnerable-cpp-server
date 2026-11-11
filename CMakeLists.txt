cmake_minimum_required(VERSION 3.14)
project(SecureLab CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(server
    main.cpp
    auth.cpp
    documents.cpp
    utils.cpp
)

target_include_directories(server PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(server PRIVATE sodium)

# Optional: enable sanitizers for testing (uncomment if needed)
# target_compile_options(server PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
# target_link_options(server PRIVATE -fsanitize=address,undefined)

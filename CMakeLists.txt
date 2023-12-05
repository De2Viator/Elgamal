cmake_minimum_required(VERSION 3.26)
project(krypto_9)

set(CMAKE_CXX_STANDARD 23)

# Найти и подключить OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Найти и подключить Boost
set(BOOST_ROOT "C:/local/boost_1_82_0")  # Путь к вашей установке Boost
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

# Исходные файлы
set(SOURCE_FILES main.cpp)

# Создать исполняемый файл
add_executable(krypto_9 ${SOURCE_FILES})

# Линковка с библиотеками OpenSSL и Boost.Multiprecision
target_link_libraries(krypto_9 OpenSSL::Crypto ${Boost_LIBRARIES})

cmake_minimum_required(VERSION 3.20)
project(CalendarServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(calendar_server src/main.cpp)

if(MSVC)
  target_compile_options(calendar_server PRIVATE /W4)
else()
  target_compile_options(calendar_server PRIVATE -Wall -Wextra -Wpedantic)
endif()

find_package(Boost 1.71 REQUIRED COMPONENTS system)
if(Boost_FOUND)
  target_include_directories(calendar_server PRIVATE ${Boost_INCLUDE_DIRS})
  target_link_libraries(calendar_server PRIVATE ${Boost_LIBRARIES})
endif()

find_package(Threads REQUIRED)

target_sources(calendar_server PRIVATE
  src/net/HttpServer.cpp
  src/net/Router.cpp
  src/observability/Metrics.cpp
  src/recurrence/Materializer.cpp
  src/recurrence/OutboxWorker.cpp
)

add_library(minijson STATIC src/net/MiniJson.cpp)
target_include_directories(minijson PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(calendar_server PRIVATE minijson)

target_sources(calendar_server PRIVATE
  src/observability/Logging.cpp
  src/config/Config.cpp
)

target_sources(calendar_server PRIVATE
  src/cache/RedisClient.cpp
)

target_sources(calendar_server PRIVATE
  src/cache/CacheKeys.cpp
)

find_package(PostgreSQL REQUIRED)
if(PostgreSQL_FOUND)
  target_include_directories(calendar_server PRIVATE ${PostgreSQL_INCLUDE_DIRS})
  target_link_libraries(calendar_server PRIVATE ${PostgreSQL_LIBRARIES})
endif()

target_sources(calendar_server PRIVATE
  src/db/DbPool.cpp
)

target_sources(calendar_server PRIVATE
  src/auth/Password.cpp
  src/auth/Jwt.cpp
)

find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
  target_link_libraries(calendar_server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()


find_library(SODIUM_LIB sodium)
if(SODIUM_LIB)
  target_link_libraries(calendar_server PRIVATE ${SODIUM_LIB})
endif()

find_library(ARGON2_LIB argon2)
find_path(ARGON2_INCLUDE_DIR argon2.h)
if(ARGON2_LIB AND ARGON2_INCLUDE_DIR)
  target_include_directories(calendar_server PRIVATE ${ARGON2_INCLUDE_DIR})
  target_compile_definitions(calendar_server PRIVATE HAVE_ARGON2)
  target_link_libraries(calendar_server PRIVATE ${ARGON2_LIB})
elseif(ARGON2_LIB)
  target_link_libraries(calendar_server PRIVATE ${ARGON2_LIB})
else()
  if(EXISTS "/lib/x86_64-linux-gnu/libargon2.so.1")
    target_link_libraries(calendar_server PRIVATE "/lib/x86_64-linux-gnu/libargon2.so.1")
  elseif(EXISTS "/usr/lib/x86_64-linux-gnu/libargon2.so.1")
    target_link_libraries(calendar_server PRIVATE "/usr/lib/x86_64-linux-gnu/libargon2.so.1")
  endif()
endif()

add_executable(db_smoke tests/db_smoke.cpp)
target_include_directories(db_smoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(PostgreSQL_FOUND)
  target_include_directories(db_smoke PRIVATE ${PostgreSQL_INCLUDE_DIRS})
  target_link_libraries(db_smoke PRIVATE ${Boost_LIBRARIES} ${PostgreSQL_LIBRARIES})
else()
  target_link_libraries(db_smoke PRIVATE ${Boost_LIBRARIES})
endif()
target_sources(db_smoke PRIVATE
  src/db/DbPool.cpp
  src/recurrence/Materializer.cpp
)

target_sources(db_smoke PRIVATE
  src/observability/Logging.cpp
)

add_test(NAME db_smoke COMMAND db_smoke)

target_include_directories(calendar_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(calendar_server PRIVATE Threads::Threads)

add_executable(http_smoke tests/http_smoke.cpp)
target_include_directories(http_smoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_sources(http_smoke PRIVATE
)
target_link_libraries(http_smoke PRIVATE ${Boost_LIBRARIES})
target_link_libraries(db_smoke PRIVATE Threads::Threads)
target_link_libraries(http_smoke PRIVATE Threads::Threads)

add_executable(rbac_http_smoke tests/rbac_http_smoke.cpp)
target_include_directories(rbac_http_smoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(rbac_http_smoke PRIVATE ${Boost_LIBRARIES} Threads::Threads)

add_executable(scenario_personal_calendar tests/scenario_personal_calendar.cpp)
target_include_directories(scenario_personal_calendar PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(scenario_personal_calendar PRIVATE ${Boost_LIBRARIES} Threads::Threads)
add_test(NAME scenario_personal_calendar COMMAND scenario_personal_calendar)

add_executable(scenario_sharing_rbac tests/scenario_sharing_rbac.cpp)
target_include_directories(scenario_sharing_rbac PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(scenario_sharing_rbac PRIVATE ${Boost_LIBRARIES} Threads::Threads)
add_test(NAME scenario_sharing_rbac COMMAND scenario_sharing_rbac)

add_executable(scenario_recurrence_exdates_overrides tests/scenario_recurrence_exdates_overrides.cpp)
target_include_directories(scenario_recurrence_exdates_overrides PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(scenario_recurrence_exdates_overrides PRIVATE ${Boost_LIBRARIES} Threads::Threads)
add_test(NAME scenario_recurrence_exdates_overrides COMMAND scenario_recurrence_exdates_overrides)

enable_testing()

add_executable(members_remove_http_smoke tests/members_remove_http_smoke.cpp)
target_include_directories(members_remove_http_smoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(members_remove_http_smoke PRIVATE ${Boost_LIBRARIES} Threads::Threads)
add_test(NAME members_remove_http_smoke COMMAND members_remove_http_smoke)

add_executable(recurrence_unit tests/recurrence_unit.cpp)
target_include_directories(recurrence_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_sources(recurrence_unit PRIVATE src/recurrence/Materializer.cpp)
target_link_libraries(recurrence_unit PRIVATE Threads::Threads)
add_test(NAME recurrence_unit COMMAND recurrence_unit)

if(PostgreSQL_FOUND)
  add_executable(overrides_unit tests/overrides_unit.cpp)
  target_include_directories(overrides_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${PostgreSQL_INCLUDE_DIRS})
  target_sources(overrides_unit PRIVATE src/recurrence/OutboxWorker.cpp src/recurrence/Materializer.cpp src/db/DbPool.cpp src/observability/Logging.cpp src/net/MiniJson.cpp)
  target_link_libraries(overrides_unit PRIVATE Threads::Threads ${PostgreSQL_LIBRARIES} minijson ${Boost_LIBRARIES})

  add_executable(exdates_unit tests/exdates_unit.cpp)
  target_include_directories(exdates_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${PostgreSQL_INCLUDE_DIRS})
  target_sources(exdates_unit PRIVATE src/recurrence/OutboxWorker.cpp src/recurrence/Materializer.cpp src/db/DbPool.cpp src/observability/Logging.cpp src/net/MiniJson.cpp)
  target_link_libraries(exdates_unit PRIVATE Threads::Threads ${PostgreSQL_LIBRARIES} minijson ${Boost_LIBRARIES})
  add_test(NAME overrides_unit COMMAND overrides_unit)
  add_test(NAME exdates_unit COMMAND exdates_unit)
endif()


add_executable(json_parse_unit tests/json_parse_unit.cpp)
target_include_directories(json_parse_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(json_parse_unit PRIVATE Threads::Threads minijson)

add_executable(json_parse_strings tests/json_parse_strings.cpp)
target_include_directories(json_parse_strings PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(json_parse_strings PRIVATE Threads::Threads minijson)

add_executable(cache_keys_unit tests/cache_keys_unit.cpp)
target_include_directories(cache_keys_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_sources(cache_keys_unit PRIVATE src/cache/CacheKeys.cpp)
target_link_libraries(cache_keys_unit PRIVATE Threads::Threads ${Boost_LIBRARIES})
add_test(NAME cache_keys_unit COMMAND cache_keys_unit)

add_executable(config_unit tests/config_unit.cpp)
target_include_directories(config_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_sources(config_unit PRIVATE src/config/Config.cpp)
target_link_libraries(config_unit PRIVATE Threads::Threads ${Boost_LIBRARIES})
add_test(NAME config_unit COMMAND config_unit)



add_executable(auth_unit tests/auth_unit.cpp)
target_include_directories(auth_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_sources(auth_unit PRIVATE src/auth/Password.cpp src/auth/Jwt.cpp)
target_link_libraries(auth_unit PRIVATE Threads::Threads OpenSSL::Crypto minijson ${Boost_LIBRARIES})
add_test(NAME auth_unit COMMAND auth_unit)

add_executable(minijson_unit tests/minijson_unit.cpp)
target_include_directories(minijson_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(minijson_unit PRIVATE Threads::Threads minijson)
add_test(NAME minijson_unit COMMAND minijson_unit)

add_executable(router_unit tests/router_unit.cpp)
target_include_directories(router_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_sources(router_unit PRIVATE src/net/Router.cpp)
target_link_libraries(router_unit PRIVATE Threads::Threads ${Boost_LIBRARIES} minijson)
add_test(NAME router_unit COMMAND router_unit)


add_executable(metrics_unit tests/metrics_unit.cpp)
target_include_directories(metrics_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_sources(metrics_unit PRIVATE src/observability/Metrics.cpp)
target_link_libraries(metrics_unit PRIVATE Threads::Threads ${Boost_LIBRARIES})
add_test(NAME metrics_unit COMMAND metrics_unit)


add_executable(logging_unit tests/logging_unit.cpp)
target_include_directories(logging_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_sources(logging_unit PRIVATE src/observability/Logging.cpp)
target_link_libraries(logging_unit PRIVATE Threads::Threads ${Boost_LIBRARIES})
add_test(NAME logging_unit COMMAND logging_unit)


add_executable(redis_client_unit tests/redis_client_unit.cpp)
target_include_directories(redis_client_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_sources(redis_client_unit PRIVATE src/cache/RedisClient.cpp src/cache/CacheKeys.cpp src/cache/Resp.cpp)
target_link_libraries(redis_client_unit PRIVATE Threads::Threads ${Boost_LIBRARIES})
add_test(NAME redis_client_unit COMMAND redis_client_unit)

foreach(name IN ITEMS dbpool_unit_basic dbpool_unit_errors dbpool_unit_cmdtuples dbpool_unit_nulls dbpool_unit_stress)
  add_executable(${name} tests/${name}.cpp)
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/tests/include)
  target_sources(${name} PRIVATE src/db/DbPool.cpp tests/fake_libpq.cpp src/observability/Logging.cpp)
  target_link_libraries(${name} PRIVATE Threads::Threads ${Boost_LIBRARIES})
  add_test(NAME ${name} COMMAND ${name})
endforeach()


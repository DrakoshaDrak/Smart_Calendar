cmake_minimum_required(VERSION 3.16)
project(desktop_qt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)

set(BUILD_DESKTOP_APP ON CACHE BOOL "Build the desktop_app (requires Qt WebEngine)")

find_package(Qt6 REQUIRED COMPONENTS Core Network)

if(BUILD_DESKTOP_APP)
  find_package(Qt6 REQUIRED COMPONENTS Widgets)
endif()

find_package(Qt6 COMPONENTS WebEngineWidgets WebEngineCore QUIET)

if (BUILD_DESKTOP_APP AND NOT Qt6WebEngineWidgets_FOUND)
  message(FATAL_ERROR
    "Qt6 WebEngine not found (Qt6WebEngineWidgets). Install Qt6 WebEngine dev packages.\n"
    "Debian/Ubuntu example: sudo apt install qt6-webengine-dev libqt6webenginecore6 libqt6webenginewidgets6\n"
    "Or install via the official Qt installer with WebEngine enabled.")
endif()

if(BUILD_DESKTOP_APP)
  add_executable(desktop_app
      src/main.cpp
      src/LocalWebServer.cpp
      src/LocalWebServer.h
      src/DesktopApp.cpp
      src/DesktopApp.h
      src/CustomWebPage.cpp
      src/CustomWebPage.h
  )

  target_include_directories(desktop_app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

  target_link_libraries(desktop_app PRIVATE
    Qt6::Widgets Qt6::Network Qt6::WebEngineWidgets Qt6::WebEngineCore
  )
endif()

add_executable(smoke_test
  tests/smoke_test.cpp
  src/LocalWebServer.cpp
  src/LocalWebServer.h
)
target_include_directories(smoke_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(smoke_test PRIVATE Qt6::Core Qt6::Network)

include(CTest)
enable_testing()
add_test(NAME smoke_test COMMAND smoke_test)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

project (SigningApp)

if (NOT MSVC)
	add_definitions(-std=c++11)
endif()

set(CMAKE_INCLUDE_CURRENTUI_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt5Core)
find_package(Qt5Gui)
find_package(Qt5Widgets)

find_package(OpenSSL)

include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB SIGNING_APP_SRCS 
	"${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
)

file(GLOB SIGNING_APP_HDRS 
	"${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
)

file(GLOB SIGNING_APP_FORMS 
	"${CMAKE_CURRENT_SOURCE_DIR}/*.ui"
)

add_executable(SigningApp WIN32
	${SIGNING_APP_SRCS}
	${SIGNING_APP_HDRS}
	${SIGNING_APP_FORMS}
)

set(SIGNING_APP_LIBRARIES
	Qt5::Core
	Qt5::Gui
	Qt5::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_link_libraries (SigningApp
	PRIVATE
	${SIGNING_APP_LIBRARIES}
)

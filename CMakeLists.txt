cmake_minimum_required(VERSION 3.5)

project(mongoose)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY   "${mongoose_SOURCE_DIR}/build")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DMG_ENABLE_SSL -DMG_ENABLE_IPV6 -DMG_ENABLE_DNS_SERVER -DMG_ENABLE_GETADDRINFO -DMG_ENABLE_THREAD -DBANDURA_MODS")

file(MAKE_DIRECTORY "${mongoose_SOURCE_DIR}/build")

set(mcp_BINARY_DIR "${mongoose_SOURCE_DIR}/build")

#add_custom_command(
#        OUTPUT mongoose.c mongoose.h
#        COMMAND ${mongoose_SOURCE_DIR}/tools/amalgam  --prefix=MG --public-header=mongoose.h $\(cat "${mongoose_SOURCE_DIR}/mongoose.c.manifest" \) > mongoose.c
#        COMMAND ${mongoose_SOURCE_DIR}/tools/amalgam  --prefix=MG --public-header=mongoose.h $\(cat "${mongoose_SOURCE_DIR}/mongoose.c.manifest" \) > "${mongoose_SOURCE_DIR}/mongoose.c"
#        COMMAND ${mongoose_SOURCE_DIR}/tools/amalgam  --prefix=MG $\(cat "${mongoose_SOURCE_DIR}/mongoose.h.manifest" \) > mongoose.h
#        COMMAND ${mongoose_SOURCE_DIR}/tools/amalgam  --prefix=MG $\(cat "${mongoose_SOURCE_DIR}/mongoose.h.manifest" \) > "${mongoose_SOURCE_DIR}/mongoose.h"
#)

add_executable(test_http tests/test_http.c mongoose.c)
target_link_libraries(test_http ssl crypto)

#add_executable(test_http_aio tests/test_http_aio.c mongoose.c)
#target_link_libraries(test_http_aio ssl crypto)

add_executable(test_ssl tests/test_ssl.c mongoose.c)
target_link_libraries(test_ssl ssl crypto)

add_library(mongoose STATIC mongoose.c)

install(TARGETS mongoose DESTINATION lib)
install(FILES mongoose.h DESTINATION include)

add_custom_target(install_mongoose
        sudo $(MAKE) install
        DEPENDS mongoose
        COMMENT "Installing libmongoose")
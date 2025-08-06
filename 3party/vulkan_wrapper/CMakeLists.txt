project(vulkan_wrapper)

set(SRC
  vulkan_wrapper.cpp
  vulkan_wrapper.h
)

add_library(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} PUBLIC Vulkan::Headers)

target_include_directories(${PROJECT_NAME} PUBLIC .)

if (PLATFORM_LINUX)
  target_compile_definitions(${PROJECT_NAME} PRIVATE VK_USE_PLATFORM_XLIB_KHR)
endif()

# dlopen
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_DL_LIBS})

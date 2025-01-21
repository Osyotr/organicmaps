project(world_feed_integration_tests)

set(SRC world_feed_integration_tests.cpp)

omim_add_test(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME}
  world_feed
  generator
)

# This test requires additional data from the other repository
if(NOT TEST_DATA_REPO_URL)
  set(TEST_DATA_REPO_URL "https://github.com/organicmaps/world_feed_integration_tests_data.git")
endif()

include(ExternalProject)
ExternalProject_Add(world_feed_integration_tests_data
  GIT_REPOSITORY    "${TEST_DATA_REPO_URL}"
  GIT_TAG           master
  SOURCE_DIR        "${OMIM_DATA_DIR}/test_data/world_feed_integration_tests_data"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   ""
)

add_dependencies(world_feed_integration_tests world_feed_integration_tests_data)

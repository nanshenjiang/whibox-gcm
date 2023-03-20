message(STATUS "${PROJECT_NAME} TEST ON")

set(TEST_BUILD_NAME test_aes)
add_executable(${TEST_BUILD_NAME} test_local.c test_aes.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto)

set(TEST_BUILD_NAME test_wbaes)
add_executable(${TEST_BUILD_NAME} test_local.c test_wbaes.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto)

set(TEST_BUILD_NAME test_wbaes_wbgcm_ee)
add_executable(${TEST_BUILD_NAME} test_local.c test_wbaes_wbgcm_ee.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto)

set(TEST_BUILD_NAME test_wbaes_wbgcm_ee2)
add_executable(${TEST_BUILD_NAME} test_local.c test_wbaes_wbgcm_ee2.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto)

set(TEST_BUILD_NAME test_wbaes_wbgcm_mask)
add_executable(${TEST_BUILD_NAME} test_local.c test_wbaes_wbgcm_mask.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto)

set(TEST_BUILD_NAME test_performance)
add_executable(${TEST_BUILD_NAME} test_local.c test_performance.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto)

set(TEST_BUILD_NAME test)
add_executable(${TEST_BUILD_NAME} test_local.c test.c)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} wbcrypto)
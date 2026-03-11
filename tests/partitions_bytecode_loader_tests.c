/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_buf.h>
#include <aws/sdkutils/partitions.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/testing/aws_test_harness.h>

AWS_TEST_CASE(partitions_bytecode_loader_basic, s_test_partitions_bytecode_loader_basic)
static int s_test_partitions_bytecode_loader_basic(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_sdkutils_library_init(allocator);

    struct aws_byte_buf bytecode;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&bytecode, allocator, "sample_partitions.bin"));

    struct aws_partitions_config *partitions =
        aws_partitions_config_new_from_bytecode(allocator, aws_byte_cursor_from_buf(&bytecode));
    ASSERT_NOT_NULL(partitions);

    ASSERT_UINT_EQUALS(1, aws_hash_table_get_entry_count(&partitions->base_partitions));
    ASSERT_UINT_EQUALS(23, aws_hash_table_get_entry_count(&partitions->region_to_partition_info));

    aws_partitions_config_release(partitions);
    aws_byte_buf_clean_up(&bytecode);
    aws_sdkutils_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(partitions_bytecode_compiler_loader_roundtrip, s_test_partitions_bytecode_compiler_loader_roundtrip)
static int s_test_partitions_bytecode_compiler_loader_roundtrip(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_sdkutils_library_init(allocator);

    struct aws_byte_buf bytecode;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&bytecode, allocator, "partitions.bin"));

    struct aws_partitions_config *partitions =
        aws_partitions_config_new_from_bytecode(allocator, aws_byte_cursor_from_buf(&bytecode));
    ASSERT_NOT_NULL(partitions);

    ASSERT_UINT_EQUALS(7, aws_hash_table_get_entry_count(&partitions->base_partitions));
    ASSERT_UINT_EQUALS(40, aws_hash_table_get_entry_count(&partitions->region_to_partition_info));

    aws_partitions_config_release(partitions);
    aws_byte_buf_clean_up(&bytecode);
    aws_sdkutils_library_clean_up();

    return AWS_OP_SUCCESS;
}

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/hash_table.h>
#include <aws/common/ref_count.h>
#include <aws/common/string.h>
#include <aws/sdkutils/partitions.h>
#include <aws/sdkutils/private/endpoints_regex.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/sdkutils/private/endpoints_util.h>

#define PART_MAGIC 0x50415254 /* "PART" */

static int s_read_u16(struct aws_byte_cursor *cur, uint16_t *out) {
    if (cur->len < 2) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out = (uint16_t)cur->ptr[0] | ((uint16_t)cur->ptr[1] << 8);
    aws_byte_cursor_advance(cur, 2);
    return AWS_OP_SUCCESS;
}

static int s_read_u32(struct aws_byte_cursor *cur, uint32_t *out) {
    if (cur->len < 4) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out = (uint32_t)cur->ptr[0] | ((uint32_t)cur->ptr[1] << 8) | ((uint32_t)cur->ptr[2] << 16) |
           ((uint32_t)cur->ptr[3] << 24);
    aws_byte_cursor_advance(cur, 4);
    return AWS_OP_SUCCESS;
}

static int s_read_u8(struct aws_byte_cursor *cur, uint8_t *out) {
    if (cur->len < 1) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out = cur->ptr[0];
    aws_byte_cursor_advance(cur, 1);
    return AWS_OP_SUCCESS;
}

static int s_read_ref(struct aws_byte_cursor *cur, struct aws_byte_cursor blob, struct aws_byte_cursor *out) {
    uint16_t offset, length;
    if (s_read_u16(cur, &offset) || s_read_u16(cur, &length)) {
        return AWS_OP_ERR;
    }
    if ((size_t)offset + length > blob.len) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out = aws_byte_cursor_from_array(blob.ptr + offset, length);
    return AWS_OP_SUCCESS;
}

static void s_callback_partition_info_destroy(void *data) {
    aws_partition_info_destroy(data);
}

static void s_partitions_config_destroy(void *data) {
    if (!data) {
        return;
    }
    struct aws_partitions_config *partitions = data;
    aws_string_destroy(partitions->version);
    aws_hash_table_clean_up(&partitions->base_partitions);
    aws_hash_table_clean_up(&partitions->region_to_partition_info);
    if (partitions->blob_copy) {
        aws_mem_release(partitions->allocator, partitions->blob_copy);
    }
    aws_mem_release(partitions->allocator, partitions);
}

struct aws_partitions_config *aws_partitions_config_new_from_bytecode(
    struct aws_allocator *allocator,
    struct aws_byte_cursor bytecode) {

    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&bytecode));

    struct aws_partitions_config *partitions = aws_mem_calloc(allocator, 1, sizeof(struct aws_partitions_config));
    partitions->allocator = allocator;
    partitions->json_root = NULL;

    /* magic */
    uint32_t magic;
    if (s_read_u32(&bytecode, &magic) || magic != PART_MAGIC) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Invalid bytecode magic.");
        aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_PARSE_FAILED);
        goto on_error;
    }

    /* string blob — copy it so name cursors remain valid after caller frees bytecode */
    uint32_t blob_size;
    if (s_read_u32(&bytecode, &blob_size) || bytecode.len < blob_size) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Invalid string blob size.");
        aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_PARSE_FAILED);
        goto on_error;
    }
    partitions->blob_copy = aws_mem_calloc(allocator, 1, blob_size);
    partitions->blob_len = blob_size;
    memcpy(partitions->blob_copy, bytecode.ptr, blob_size);
    struct aws_byte_cursor blob = aws_byte_cursor_from_array(partitions->blob_copy, blob_size);
    aws_byte_cursor_advance(&bytecode, blob_size);

    /* version */
    struct aws_byte_cursor version_cur;
    if (s_read_ref(&bytecode, blob, &version_cur)) {
        goto on_error;
    }
    partitions->version = aws_string_new_from_cursor(allocator, &version_cur);

    /* init hash tables */
    if (aws_hash_table_init(
            &partitions->base_partitions,
            allocator,
            10,
            aws_hash_byte_cursor_ptr,
            aws_endpoints_byte_cursor_eq,
            NULL,
            s_callback_partition_info_destroy)) {
        goto on_error;
    }

    if (aws_hash_table_init(
            &partitions->region_to_partition_info,
            allocator,
            20,
            aws_hash_byte_cursor_ptr,
            aws_endpoints_byte_cursor_eq,
            NULL,
            s_callback_partition_info_destroy)) {
        goto on_error;
    }

    /* partition count */
    uint16_t partition_count;
    if (s_read_u16(&bytecode, &partition_count)) {
        goto on_error;
    }

    for (uint16_t i = 0; i < partition_count; ++i) {
        struct aws_byte_cursor id_cur, outputs_cur, regex_cur;
        if (s_read_ref(&bytecode, blob, &id_cur) || s_read_ref(&bytecode, blob, &outputs_cur) ||
            s_read_ref(&bytecode, blob, &regex_cur)) {
            goto on_error;
        }

        struct aws_partition_info *base = aws_partition_info_new(allocator, id_cur);
        base->info = aws_string_new_from_cursor(allocator, &outputs_cur);

        if (regex_cur.len > 0) {
            base->region_regex = aws_endpoints_regex_new(allocator, regex_cur);
            if (!base->region_regex) {
                aws_partition_info_destroy(base);
                goto on_error;
            }
        }

        if (aws_hash_table_put(&partitions->base_partitions, &base->name, base, NULL)) {
            aws_partition_info_destroy(base);
            goto on_error;
        }

        uint16_t region_count;
        if (s_read_u16(&bytecode, &region_count)) {
            goto on_error;
        }

        for (uint16_t j = 0; j < region_count; ++j) {
            struct aws_byte_cursor region_name_cur;
            uint8_t has_override;
            if (s_read_ref(&bytecode, blob, &region_name_cur) || s_read_u8(&bytecode, &has_override)) {
                goto on_error;
            }

            struct aws_partition_info *region_info = aws_partition_info_new(allocator, region_name_cur);

            if (has_override) {
                struct aws_byte_cursor merged_cur;
                if (s_read_ref(&bytecode, blob, &merged_cur)) {
                    aws_partition_info_destroy(region_info);
                    goto on_error;
                }
                region_info->info = aws_string_new_from_cursor(allocator, &merged_cur);
                region_info->is_copy = false;
            } else {
                region_info->info = base->info;
                region_info->is_copy = true;
            }

            if (aws_hash_table_put(&partitions->region_to_partition_info, &region_info->name, region_info, NULL)) {
                aws_partition_info_destroy(region_info);
                goto on_error;
            }
        }
    }

    aws_ref_count_init(&partitions->ref_count, partitions, s_partitions_config_destroy);
    return partitions;

on_error:
    s_partitions_config_destroy(partitions);
    return NULL;
}

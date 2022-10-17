/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/sdkutils/partitions.h>
#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>
#include <aws/common/json.h>
#include <aws/common/hash_table.h>
#include <aws/common/ref_count.h>
#include <aws/common/string.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>

static struct aws_byte_cursor s_supported_version = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("1.0");

struct aws_byte_cursor aws_partitions_get_supported_version(void) {
    return s_supported_version;
}

static void s_partitions_config_destroy(void *data) {
    if (data == NULL) {
        return;
    }

    struct aws_partitions_config *partitions = data;

    aws_json_value_destroy(partitions->json_root);

    aws_string_destroy(partitions->version);

    aws_hash_table_clean_up(&partitions->region_to_partition_info);

    aws_mem_release(partitions->allocator, partitions);
}

struct region_merge_wrapper {
    struct aws_json_value *outputs_node;
    struct aws_json_value *merge_node;
};

static int s_on_region_merge(
    const struct aws_byte_cursor *key,
    const struct aws_json_value *value,
    bool *out_should_continue,
    void *user_data) {
    (void)out_should_continue;
    
    struct region_merge_wrapper *merge = user_data;

    if (merge->merge_node == NULL) {
        merge->merge_node = aws_json_value_duplicate(merge->outputs_node);
    }

    if (aws_json_value_remove_from_object(merge->merge_node, *key)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to remove previous partition value.");
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_PARSE_FAILED);
    }
    
    if (aws_json_value_add_to_object(merge->merge_node, *key, aws_json_value_duplicate(value))) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to overwrite partition data.");
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_PARSE_FAILED);
    }

    return AWS_OP_SUCCESS;
}

struct partition_parse_wrapper {
    struct aws_partitions_config *partitions;
    struct aws_json_value *outputs_node;
    struct aws_string *outputs_str;
};

static int s_on_region_element(
    const struct aws_byte_cursor *key,
    const struct aws_json_value *value,
    bool *out_should_continue,
    void *user_data) {
    (void)out_should_continue;
    
    struct aws_partition_info *partition_info = NULL;
    struct partition_parse_wrapper *wrapper = user_data;

    struct region_merge_wrapper merge = {
        .outputs_node = wrapper->outputs_node,
        .merge_node = NULL,
    };

    if (aws_json_const_iterate_object(value, s_on_region_merge, &merge)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to parse partitions.");
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_PARSE_FAILED);
    }

    if (merge.merge_node != NULL) {
        partition_info = aws_partition_info_new(wrapper->partitions->allocator, *key);
        partition_info->info = aws_string_new_from_json_value(wrapper->partitions->allocator, merge.merge_node);
        aws_json_value_destroy(merge.merge_node);
    } else {
        partition_info = aws_partition_info_new(wrapper->partitions->allocator, *key);
        partition_info->info = wrapper->outputs_str;
        partition_info->is_copy = true;
    }

    if (aws_hash_table_put(&wrapper->partitions->region_to_partition_info,
        &partition_info->name, partition_info, NULL)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to add partition info.");
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:
    if (partition_info != NULL) {
        aws_partition_info_destroy(partition_info);
    }
    return aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_PARSE_FAILED); 
}

static int s_on_partition_element(
    size_t idx,
    const struct aws_json_value *partition_node,
    bool *out_should_continue,
    void *user_data) {
    (void)out_should_continue;
    (void)idx;

    struct aws_partitions_config *partitions = user_data;

    struct aws_byte_cursor id_cur;
    struct aws_json_value *id_node = aws_json_value_get_from_object(partition_node, aws_byte_cursor_from_c_str("id"));
    if (id_node == NULL || aws_json_value_get_string(id_node, &id_cur)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to extract id of partition.");
        goto on_error;
    }

    struct aws_json_value *outputs_node = aws_json_value_get_from_object(partition_node,
        aws_byte_cursor_from_c_str("outputs"));
    if (outputs_node == NULL) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to extract outputs of partition.");
        goto on_error;
    }

    struct aws_partition_info *partition_info = aws_partition_info_new(partitions->allocator, id_cur);
    partition_info->info = aws_string_new_from_json_value(partitions->allocator, outputs_node);

    if (partition_info->info == NULL) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to add partition info.");
        goto on_error;
    }

    if (aws_hash_table_put(&partitions->region_to_partition_info, &partition_info->name, partition_info, NULL)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to add partition info.");
        goto on_error;
    }

    struct partition_parse_wrapper wrapper = {
        .outputs_node = outputs_node,
        .outputs_str = partition_info->info,
        .partitions = partitions
    };

    struct aws_json_value *regions_node = aws_json_value_get_from_object(partition_node, aws_byte_cursor_from_c_str("regions"));
    if (regions_node != NULL && aws_json_const_iterate_object(regions_node, s_on_region_element, &wrapper)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to parse regions.");
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:
    return aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_PARSE_FAILED);
}

static int s_init_partitions_config_from_json(
    struct aws_allocator *allocator,
    struct aws_partitions_config *partitions,
    struct aws_byte_cursor partitions_cur) {
    
    struct aws_json_value *root = aws_json_value_new_from_string(allocator, partitions_cur);

    if (root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to parse provided string as json.");
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_PARSE_FAILED);
    }

    partitions->json_root = root;

    struct aws_byte_cursor version_cur;
    struct aws_json_value *version_node = aws_json_value_get_from_object(root, aws_byte_cursor_from_c_str("version"));
    if (version_node == NULL || aws_json_value_get_string(version_node, &version_cur)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to extract version.");
        aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_UNSUPPORTED);
        goto on_error;
    }

#ifdef ENDPOINTS_VERSION_CHECK /* TODO: samples are currently inconsistent with versions. skip check for now */
    if (!aws_byte_cursor_eq_c_str(&version_cur, &s_supported_version)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Unsupported partitions version.");
        aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_UNSUPPORTED);
        goto on_error;
    }
#endif

    struct aws_json_value *partitions_node = aws_json_value_get_from_object(root, aws_byte_cursor_from_c_str("partitions"));
    if (partitions_node == NULL || aws_json_const_iterate_array(partitions_node, s_on_partition_element, partitions)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to parse partitions.");
        aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_PARSE_FAILED);
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:
    return AWS_OP_ERR;
}

static void s_callback_partition_info_destroy(void *data) {
    struct aws_partition_info *info = data;
    aws_partition_info_destroy(info);
}

struct aws_partitions_config *aws_partitions_config_new_from_string(
    struct aws_allocator *allocator,
    struct aws_byte_cursor partitions_cur) {
    
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&partitions_cur));

    struct aws_partitions_config *partitions = aws_mem_calloc(allocator, 1, sizeof(struct aws_partitions_config));
    partitions->allocator = allocator;

    if(aws_hash_table_init(
        &partitions->region_to_partition_info,
        allocator,
        20,
        aws_hash_byte_cursor_ptr,
        aws_endpoints_byte_cursor_eq,
        NULL,
        s_callback_partition_info_destroy)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_PARTITIONS_PARSING, "Failed to init partition info map.");
        aws_raise_error(AWS_ERROR_SDKUTILS_PARTITIONS_PARSE_FAILED);
        return NULL;
    }

    if (s_init_partitions_config_from_json(allocator, partitions, partitions_cur)) {
        s_partitions_config_destroy(partitions);
        return NULL;
    }

    aws_ref_count_init(&partitions->ref_count, partitions, s_partitions_config_destroy);

    return partitions;
}

struct aws_partitions_config *aws_partitions_config_acquire(struct aws_partitions_config *partitions) {
    AWS_PRECONDITION(partitions);
    if (partitions) {
        aws_ref_count_acquire(&partitions->ref_count);
    }
    return partitions;
}

struct aws_partitions_config *aws_partitions_config_release(struct aws_partitions_config *partitions) {
    if (partitions) {
        aws_ref_count_release(&partitions->ref_count);
    }
    return NULL;
}

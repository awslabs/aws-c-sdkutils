/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/common/hash_table.h>
#include <aws/common/json.h>
#include <aws/common/string.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/sdkutils/private/endpoints_util.h>

static void s_on_condition_array_element_clean_up(void *element) {
    struct aws_endpoints_condition *condition = element;
    aws_endpoints_condition_clean_up(condition);
}

static void s_on_rule_array_element_clean_up(void *element) {
    struct aws_endpoints_rule *rule = element;
    aws_endpoints_rule_clean_up(rule);
}

static void s_on_expr_array_element_clean_up(void *element) {
    struct aws_endpoints_expr *expr = element;
    aws_endpoints_expr_clean_up(expr);
}

struct aws_partition_info *aws_partition_info_new(struct aws_allocator *allocator, struct aws_byte_cursor name) {
    AWS_PRECONDITION(allocator);
    struct aws_partition_info *partition_info = aws_mem_calloc(allocator, 1, sizeof(struct aws_partition_info));

    partition_info->allocator = allocator;
    partition_info->name = name;

    return partition_info;
}

void aws_partition_info_destroy(struct aws_partition_info *partition_info) {
    if (partition_info == NULL) {
        return;
    }

    if (!partition_info->is_copy) {
        aws_string_destroy(partition_info->info);
    }

    aws_mem_release(partition_info->allocator, partition_info);
}

struct aws_endpoints_parameter *aws_endpoints_parameter_new(
    struct aws_allocator *allocator,
    struct aws_byte_cursor name) {
    AWS_PRECONDITION(allocator);
    struct aws_endpoints_parameter *parameter = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_parameter));

    parameter->allocator = allocator;
    parameter->name = name;

    return parameter;
}

void aws_endpoints_parameter_destroy(struct aws_endpoints_parameter *parameter) {
    if (parameter == NULL) {
        return;
    }

    aws_mem_release(parameter->allocator, parameter);
}

void aws_endpoints_rule_clean_up(struct aws_endpoints_rule *rule) {
    AWS_PRECONDITION(rule);

    aws_array_list_deep_clean_up(&rule->conditions, s_on_condition_array_element_clean_up);

    switch (rule->type) {
        case AWS_ENDPOINTS_RULE_ENDPOINT:
            aws_endpoints_rule_data_endpoint_clean_up(&rule->rule_data.endpoint);
            break;
        case AWS_ENDPOINTS_RULE_ERROR:
            aws_endpoints_rule_data_error_clean_up(&rule->rule_data.error);
            break;
        case AWS_ENDPOINTS_RULE_TREE:
            aws_endpoints_rule_data_tree_clean_up(&rule->rule_data.tree);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    AWS_ZERO_STRUCT(*rule);
}

void aws_endpoints_rule_data_endpoint_clean_up(struct aws_endpoints_rule_data_endpoint *rule_data) {
    AWS_PRECONDITION(rule_data);

    aws_endpoints_expr_clean_up(&rule_data->url);

    aws_byte_buf_clean_up(&rule_data->properties);
    aws_hash_table_clean_up(&rule_data->headers);

    AWS_ZERO_STRUCT(*rule_data);
}

void aws_endpoints_rule_data_error_clean_up(struct aws_endpoints_rule_data_error *rule_data) {
    AWS_PRECONDITION(rule_data);

    aws_endpoints_expr_clean_up(&rule_data->error);

    AWS_ZERO_STRUCT(*rule_data);
}

void aws_endpoints_rule_data_tree_clean_up(struct aws_endpoints_rule_data_tree *rule_data) {
    AWS_PRECONDITION(rule_data);

    aws_array_list_deep_clean_up(&rule_data->rules, s_on_rule_array_element_clean_up);
    AWS_ZERO_STRUCT(*rule_data);
}

void aws_endpoints_condition_clean_up(struct aws_endpoints_condition *condition) {
    AWS_PRECONDITION(condition);

    aws_endpoints_expr_clean_up(&condition->expr);
    AWS_ZERO_STRUCT(*condition);
}

void aws_endpoints_function_clean_up(struct aws_endpoints_function *function) {
    AWS_PRECONDITION(function);

    aws_array_list_deep_clean_up(&function->argv, s_on_expr_array_element_clean_up);
    AWS_ZERO_STRUCT(*function);
}

void aws_endpoints_expr_clean_up(struct aws_endpoints_expr *expr) {
    AWS_PRECONDITION(expr);

    switch (expr->type) {
        case AWS_ENDPOINTS_EXPR_STRING:
        case AWS_ENDPOINTS_EXPR_BOOLEAN:
        case AWS_ENDPOINTS_EXPR_NUMBER:
        case AWS_ENDPOINTS_EXPR_REFERENCE:
            break;
        case AWS_ENDPOINTS_EXPR_FUNCTION:
            aws_endpoints_function_clean_up(&expr->e.function);
            break;
        case AWS_ENDPOINTS_EXPR_ARRAY:
            aws_array_list_deep_clean_up(&expr->e.array, s_on_expr_array_element_clean_up);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    AWS_ZERO_STRUCT(*expr);
}
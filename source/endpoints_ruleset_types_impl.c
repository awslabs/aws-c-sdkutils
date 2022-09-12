/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/common/hash_table.h>
#include <aws/common/string.h>
#include <aws/sdkutils/private/endpoints_ruleset_types_impl.h>

static void s_on_condition_array_element_destroy(void *element) {
    struct aws_endpoints_condition *condition = element;
    aws_endpoints_condition_cleanup(condition);
}

static void s_on_rule_array_element_destroy(void *element) {
    struct aws_endpoints_rule *rule = element;
    aws_endpoints_rule_destroy(rule);
}

static void s_on_expr_array_element_cleanup(void *element) {
    struct aws_endpoints_expr *expr = element;
    aws_endpoints_expr_cleanup(expr);
}

void aws_array_list_deep_cleanup(struct aws_array_list *array, aws_array_callback_destroy_fn on_destroy_element) {
    for (size_t idx = 0; idx < aws_array_list_length(array); ++idx) {
        void *element = NULL;

        aws_array_list_get_at(array, &element, idx);
        AWS_ASSERT(element);
        on_destroy_element(element);
    }
    aws_array_list_clean_up(array);
}

void aws_array_list_deep_value_cleanup(struct aws_array_list *array, aws_array_callback_destroy_fn on_destroy_element) {
    for (size_t idx = 0; idx < aws_array_list_length(array); ++idx) {
        void *element = NULL;

        aws_array_list_get_at_ptr(array, &element, idx);
        AWS_ASSERT(element);
        on_destroy_element(element);
    }
    aws_array_list_clean_up(array);
}

struct aws_endpoints_parameter *aws_endpoints_parameter_new(
    struct aws_allocator *allocator,
    enum aws_endpoints_parameter_value_type type,
    const struct aws_byte_cursor *name_cur) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(name_cur);
    struct aws_endpoints_parameter *parameter = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_parameter));

    parameter->allocator = allocator;
    parameter->type = type;
    parameter->name = aws_string_new_from_cursor(allocator, name_cur);
    parameter->name_cur = aws_byte_cursor_from_string(parameter->name);

    return parameter;
}

void aws_endpoints_parameter_destroy(struct aws_endpoints_parameter *parameter) {
    aws_string_destroy(parameter->name);
    aws_string_destroy(parameter->built_in);
    if (parameter->type == AWS_ENDPOINTS_PARAMETER_STRING) {
        aws_string_destroy(parameter->default_value.string);
    }
    aws_string_destroy(parameter->documentation);
    aws_string_destroy(parameter->deprecated_message);
    aws_string_destroy(parameter->deprecated_since);

    aws_mem_release(parameter->allocator, parameter);
}

struct aws_endpoints_rule *aws_endpoints_rule_new(struct aws_allocator *allocator, enum aws_endpoints_rule_type type) {

    struct aws_endpoints_rule *rule = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_rule));

    rule->allocator = allocator;
    rule->type = type;

    return rule;
}

void aws_endpoints_rule_destroy(struct aws_endpoints_rule *rule) {
    aws_array_list_deep_value_cleanup(&rule->conditions, s_on_condition_array_element_destroy);

    switch (rule->type) {
        case AWS_ENDPOINTS_RULE_ENDPOINT:
            aws_endpoints_rule_data_endpoint_destroy(rule->rule_data.endpoint);
            break;
        case AWS_ENDPOINTS_RULE_ERROR:
            aws_endpoints_rule_data_error_destroy(rule->rule_data.error);
            break;
        case AWS_ENDPOINTS_RULE_TREE:
            aws_endpoints_rule_data_tree_destroy(rule->rule_data.tree);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    aws_string_destroy(rule->documentation);

    aws_mem_release(rule->allocator, rule);
}

struct aws_endpoints_rule_data_endpoint *aws_endpoints_rule_data_endpoint_new(struct aws_allocator *allocator) {
    struct aws_endpoints_rule_data_endpoint *rule_data =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_rule_data_endpoint));
    rule_data->allocator = allocator;

    return rule_data;
}

void aws_endpoints_rule_data_endpoint_destroy(struct aws_endpoints_rule_data_endpoint *rule_data) {

    switch (rule_data->url_type) {
        case AWS_ENDPOINTS_URL_TEMPLATE:
            aws_string_destroy(rule_data->url.template);
            break;
        case AWS_ENDPOINTS_URL_REFERENCE:
            aws_string_destroy(rule_data->url.reference);
            break;
        case AWS_ENDPOINTS_URL_FUNCTION:
            aws_endpoints_function_cleanup(&rule_data->url.function);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }

    aws_string_destroy(rule_data->properties);
    if (rule_data->headers) {
        aws_hash_table_clean_up(rule_data->headers);
        aws_mem_release(rule_data->allocator, rule_data->headers);
    }
    aws_mem_release(rule_data->allocator, rule_data);
}

struct aws_endpoints_rule_data_error *aws_endpoints_rule_data_error_new(struct aws_allocator *allocator) {
    struct aws_endpoints_rule_data_error *rule_data =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_rule_data_error));
    rule_data->allocator = allocator;
    return rule_data;
}

void aws_endpoints_rule_data_error_destroy(struct aws_endpoints_rule_data_error *rule_data) {
    switch (rule_data->error_type) {
        case AWS_ENDPOINTS_ERROR_TEMPLATE:
            aws_string_destroy(rule_data->error.template);
            break;
        case AWS_ENDPOINTS_ERROR_REFERENCE:
            aws_string_destroy(rule_data->error.reference);
            break;
        case AWS_ENDPOINTS_ERROR_FUNCTION:
            aws_endpoints_function_cleanup(&rule_data->error.function);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }
    aws_mem_release(rule_data->allocator, rule_data);
}

struct aws_endpoints_rule_data_tree *aws_endpoints_rule_data_tree_new(struct aws_allocator *allocator) {
    AWS_PRECONDITION(allocator);
    struct aws_endpoints_rule_data_tree *rule_data =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_rule_data_tree));
    rule_data->allocator = allocator;
    return rule_data;
}

void aws_endpoints_rule_data_tree_destroy(struct aws_endpoints_rule_data_tree *rule_data) {
    aws_array_list_deep_cleanup(&rule_data->rules, s_on_rule_array_element_destroy);

    aws_mem_release(rule_data->allocator, rule_data);
}

void aws_endpoints_condition_cleanup(struct aws_endpoints_condition *condition) {

    aws_string_destroy(condition->assign);
    aws_endpoints_function_cleanup(&condition->function);
}

void aws_endpoints_function_cleanup(struct aws_endpoints_function *function) {
    aws_string_destroy(function->fn);
    function->fn = NULL;

    aws_array_list_deep_value_cleanup(&function->argv, s_on_expr_array_element_cleanup);
}

void aws_endpoints_expr_cleanup(struct aws_endpoints_expr *expr) {
    switch (expr->type) {
        case AWS_ENDPOINTS_EXPR_STRING:
            aws_string_destroy(expr->e.string);
            break;
        case AWS_ENDPOINTS_EXPR_BOOLEAN:
        case AWS_ENDPOINTS_EXPR_NUMBER:
            break;
        case AWS_ENDPOINTS_EXPR_FUNCTION:
            aws_endpoints_function_cleanup(&expr->e.function);
            break;
        case AWS_ENDPOINTS_EXPR_REFERENCE:
            aws_string_destroy(expr->e.reference);
            break;
        case AWS_ENDPOINTS_EXPR_ARRAY:
            aws_array_list_deep_value_cleanup(&expr->e.array, s_on_expr_array_element_cleanup);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }
}

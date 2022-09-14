/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_SDKUTILS_ENDPOINTS_RULESET_TYPES_IMPL_H
#define AWS_SDKUTILS_ENDPOINTS_RULESET_TYPES_IMPL_H

#include <aws/common/ref_count.h>
#include <aws/sdkutils/endpoints_rule_engine.h>

enum aws_endpoints_rule_type { AWS_ENDPOINTS_RULE_ENDPOINT, AWS_ENDPOINTS_RULE_ERROR, AWS_ENDPOINTS_RULE_TREE };

enum aws_endpoints_url_type { AWS_ENDPOINTS_URL_TEMPLATE, AWS_ENDPOINTS_URL_REFERENCE, AWS_ENDPOINTS_URL_FUNCTION };

enum aws_endpoints_error_type {
    AWS_ENDPOINTS_ERROR_TEMPLATE,
    AWS_ENDPOINTS_ERROR_REFERENCE,
    AWS_ENDPOINTS_ERROR_FUNCTION
};

enum aws_endpoints_expr_type {
    AWS_ENDPOINTS_EXPR_STRING,
    AWS_ENDPOINTS_EXPR_NUMBER,
    AWS_ENDPOINTS_EXPR_BOOLEAN,
    AWS_ENDPOINTS_EXPR_ARRAY,
    AWS_ENDPOINTS_EXPR_REFERENCE,
    AWS_ENDPOINTS_EXPR_FUNCTION
};

struct aws_endpoints_parameter {
    struct aws_allocator *allocator;

    struct aws_byte_cursor name_cur;
    struct aws_string *name;

    enum aws_endpoints_value_type type;
    struct aws_string *built_in;

    union {
        struct aws_string *string;
        bool boolean;
    } default_value;

    bool is_required;
    struct aws_string *documentation;
    bool is_deprecated;
    struct aws_string *deprecated_message;
    struct aws_string *deprecated_since;
};

struct aws_endpoints_ruleset {
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;

    /* list of (aws_endpoints_rule) */
    struct aws_array_list rules;

    struct aws_string *version;
    struct aws_string *service_id;
    /* map of (aws_byte_cursor *) -> (aws_endpoints_parameter *) */
    struct aws_hash_table parameters;
};

struct aws_endpoints_function {
    struct aws_string *fn; /* TODO: precompute hash or enum value to avoid lookup on every eval */
    /* List of (aws_endpoints_expr) */
    struct aws_array_list argv;
};

struct aws_endpoints_expr {
    enum aws_endpoints_expr_type type;
    union {
        struct aws_string *string;
        double number;
        bool boolean;
        struct aws_array_list array; /* List of (aws_endpoints_expr) */
        struct aws_string *reference;
        struct aws_endpoints_function function;
    } e;
};

struct aws_endpoints_rule_data_endpoint {
    struct aws_allocator *allocator;
    enum aws_endpoints_url_type url_type;
    union {
        struct aws_string *template;
        struct aws_string *reference;
        struct aws_endpoints_function function;
    } url;

    /*
     * Note: this is a custom properties json associated with the result.
     * Properties are unstable and format can change frequently.
     * Its up to caller to parse json to retrieve properties.
     */
    struct aws_string *properties;
    /* Map of (aws_string *) -> (aws_array_list * of aws_string *) */
    struct aws_hash_table headers;
};

struct aws_endpoints_rule_data_error {
    enum aws_endpoints_error_type error_type;
    union {
        struct aws_string *template;
        struct aws_string *reference;
        struct aws_endpoints_function function;
    } error;
};

struct aws_endpoints_rule_data_tree {
    /* List of (aws_endpoints_rule) */
    struct aws_array_list rules;
};

struct aws_endpoints_condition {
    struct aws_endpoints_function function;
    struct aws_string *assign;
};

struct aws_endpoints_rule {
    struct aws_allocator *allocator;

    /* List of (aws_endpoints_condition) */
    struct aws_array_list conditions;
    struct aws_string *documentation;

    enum aws_endpoints_rule_type type;
    union {
        struct aws_endpoints_rule_data_endpoint endpoint;
        struct aws_endpoints_rule_data_error error;
        struct aws_endpoints_rule_data_tree tree;
    } rule_data;
};

struct aws_endpoints_parameter *aws_endpoints_parameter_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *name_cur);
void aws_endpoints_parameter_destroy(struct aws_endpoints_parameter *parameter);

void aws_endpoints_rule_clean_up(struct aws_endpoints_rule *rule);

void aws_endpoints_rule_data_endpoint_clean_up(struct aws_endpoints_rule_data_endpoint *rule_data);
void aws_endpoints_rule_data_error_clean_up(struct aws_endpoints_rule_data_error *rule_data);
void aws_endpoints_rule_data_tree_clean_up(struct aws_endpoints_rule_data_tree *rule_data);

void aws_endpoints_condition_clean_up(struct aws_endpoints_condition *condition);
void aws_endpoints_function_clean_up(struct aws_endpoints_function *function);
void aws_endpoints_expr_clean_up(struct aws_endpoints_expr *expr);

/*
 * Helpers to do deep clean up of array list.
 * TODO: move to aws-c-common?
 */
typedef void(aws_array_callback_clean_up_fn)(void *value);
void aws_array_list_deep_clean_up(struct aws_array_list *array, aws_array_callback_clean_up_fn on_clean_up_element);

#endif /* AWS_SDKUTILS_ENDPOINTS_RULESET_TYPES_IMPL_H */

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/array_list.h>
#include <aws/common/hash_table.h>
#include <aws/common/json.h>
#include <aws/common/ref_count.h>
#include <aws/common/string.h>
#include <aws/sdkutils/endpoints/private/ruleset_types_impl.h>

#define SKIP_DOC true

/* parameter types */
static struct aws_byte_cursor s_string_type_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("string");
static struct aws_byte_cursor s_boolean_type_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("boolean");

/* rule types */
static struct aws_byte_cursor s_endpoint_type_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("endpoint");
static struct aws_byte_cursor s_error_type_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("error");
static struct aws_byte_cursor s_tree_type_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("tree");

/* TODO: improve error messages. Include json line num? or dump json node? */

/*
******************************
* Parameter Getters.
******************************
*/
enum aws_endpoints_parameter_value_type aws_endpoints_parameter_get_value_type(
    const struct aws_endpoints_parameter *parameter) {
    AWS_PRECONDITION(parameter);
    return parameter->type;
}

const struct aws_string *aws_endpoints_parameter_get_built_in(const struct aws_endpoints_parameter *parameter) {
    AWS_PRECONDITION(parameter);
    return parameter->built_in;
}

int aws_endpoints_parameter_get_default_string(
    const struct aws_endpoints_parameter *parameter,
    struct aws_string **out_string) {
    AWS_PRECONDITION(parameter);
    AWS_PRECONDITION(out_string);

    if (parameter->type == AWS_ENDPOINTS_PARAMETER_STRING) {
        *out_string = parameter->default_value.string;
        return AWS_OP_SUCCESS;
    };

    return AWS_OP_ERR;
}

int aws_endpoints_parameter_get_default_boolean(const struct aws_endpoints_parameter *parameter, bool *out_bool) {
    AWS_PRECONDITION(parameter);
    AWS_PRECONDITION(out_bool);

    if (parameter->type == AWS_ENDPOINTS_PARAMETER_STRING) {
        *out_bool = parameter->default_value.boolean;
        return AWS_OP_SUCCESS;
    };

    return AWS_OP_ERR;
}

bool aws_endpoints_parameters_get_is_required(const struct aws_endpoints_parameter *parameter) {
    AWS_PRECONDITION(parameter);
    return parameter->is_required;
}

const struct aws_string *aws_endpoints_parameter_get_documentation(const struct aws_endpoints_parameter *parameter) {
    AWS_PRECONDITION(parameter);
    return parameter->documentation;
}

bool aws_endpoints_parameters_get_is_deprecated(const struct aws_endpoints_parameter *parameter) {
    AWS_PRECONDITION(parameter);
    return parameter->is_deprecated;
}

const struct aws_string *aws_endpoints_parameter_get_deprecated_message(
    const struct aws_endpoints_parameter *parameter) {
    AWS_PRECONDITION(parameter);
    return parameter->deprecated_message;
}

const struct aws_string *aws_endpoints_parameter_get_deprecated_since(const struct aws_endpoints_parameter *parameter) {
    AWS_PRECONDITION(parameter);
    return parameter->deprecated_since;
}

/*
******************************
* Parser getters.
******************************
*/

const struct aws_hash_table *aws_endpoints_ruleset_get_parameters(struct aws_endpoints_ruleset *ruleset) {
    AWS_PRECONDITION(ruleset);
    return ruleset->parameters;
}

const struct aws_string *aws_endpoints_ruleset_get_version(struct aws_endpoints_ruleset *ruleset) {
    AWS_PRECONDITION(ruleset);
    return ruleset->version;
}

const struct aws_string *aws_endpoints_ruleset_get_service_id(struct aws_endpoints_ruleset *ruleset) {
    AWS_PRECONDITION(ruleset);
    return ruleset->service_id;
}

/*
******************************
* Parser helpers.
******************************
*/

static void s_on_rule_array_element_destroy(void *element) {
    struct aws_endpoints_rule *rule = element;
    aws_endpoints_rule_destroy(rule);
}

static void s_on_string_array_element_destroy(void *data) {
    struct aws_string *string = data;
    aws_string_destroy(string);
}

void aws_hash_callback_endpoints_parameter_destroy(void *data) {
    struct aws_endpoints_parameter *parameter = data;
    aws_endpoints_parameter_destroy(parameter);
}

void aws_hash_callback_headers_destroy(void *data) {
    struct aws_array_list *array = data;
    aws_array_list_deep_cleanup(array, s_on_string_array_element_destroy);
    aws_array_list_clean_up(array);
}

struct array_parser_wrapper {
    struct aws_allocator *allocator;
    struct aws_array_list *array;
    bool all_elements_parsed_successfully;
};

static int s_init_array_from_json(
    struct aws_allocator *allocator,
    const struct aws_json_value *value_node,
    struct aws_array_list *values,
    aws_json_on_value_encountered_const_fn *value_fn) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(values);
    AWS_PRECONDITION(value_node);
    AWS_PRECONDITION(value_fn);

    struct array_parser_wrapper wrapper = {
        .allocator = allocator, .array = values, .all_elements_parsed_successfully = true};

    if (aws_json_const_iterate_array(value_node, value_fn, &wrapper)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Array field has unexpected type.");
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
    }

    if (!wrapper.all_elements_parsed_successfully) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

struct member_parser_wrapper {
    struct aws_allocator *allocator;
    struct aws_hash_table *table;
    bool all_members_parsed_successfully;
};

static int s_init_members_from_json(
    struct aws_allocator *allocator,
    struct aws_json_value *node,
    struct aws_hash_table *table,
    aws_json_on_member_encountered_const_fn *member_fn) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(node);
    AWS_PRECONDITION(table);

    struct member_parser_wrapper wrapper = {
        .allocator = allocator, .table = table, .all_members_parsed_successfully = true};

    if (aws_json_const_iterate_object(node, member_fn, &wrapper)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Member field has unexpected type.");
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
    }

    if (!wrapper.all_members_parsed_successfully) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/*
******************************
* Parser functions.
******************************
*/

static struct aws_endpoints_function *s_try_parse_function(
    struct aws_allocator *allocator,
    const struct aws_json_value *node);

static struct aws_endpoints_reference *s_try_parse_reference(
    struct aws_allocator *allocator,
    const struct aws_json_value *node) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(node);

    struct aws_json_value *ref_node = aws_json_value_get_from_object(node, aws_byte_cursor_from_c_str("ref"));
    if (ref_node != NULL) {
        struct aws_byte_cursor ref_cur;
        aws_json_value_get_string(ref_node, &ref_cur);
        return aws_endpoints_reference_new(allocator, aws_string_new_from_cursor(allocator, &ref_cur));
    }

    return NULL;
}

static struct aws_endpoints_expr *s_parse_expr(struct aws_allocator *allocator, const struct aws_json_value *node);

static bool s_on_expr_element(size_t idx, const struct aws_json_value *value_node, void *user_data) {
    struct array_parser_wrapper *wrapper = user_data;
    struct aws_endpoints_expr *expr = s_parse_expr(wrapper->allocator, value_node);

    if (expr == NULL) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to parse value.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        return false;
    }

    aws_array_list_push_back(wrapper->array, &expr);
    return true;
}

static struct aws_endpoints_expr *s_parse_expr(struct aws_allocator *allocator, const struct aws_json_value *node) {
    /* TODO: this recurses. in practical circumstances depth will never be high,
    but we should still consider doing iterative approach */
    if (aws_json_value_is_string(node)) {
        struct aws_byte_cursor cur;
        aws_json_value_get_string(node, &cur);
        struct aws_endpoints_expr *expr = aws_endpoints_expr_new(allocator, AWS_ENDPOINTS_EXPR_STRING);
        expr->e.string = aws_string_new_from_cursor(allocator, &cur);
        return expr;
    } else if (aws_json_value_is_number(node)) {
        double number;
        aws_json_value_get_number(node, &number);
        struct aws_endpoints_expr *expr = aws_endpoints_expr_new(allocator, AWS_ENDPOINTS_EXPR_NUMBER);
        expr->e.number = (int32_t)number;
        return expr;
    } else if (aws_json_value_is_boolean(node)) {
        bool v;
        aws_json_value_get_boolean(node, &v);
        struct aws_endpoints_expr *expr = aws_endpoints_expr_new(allocator, AWS_ENDPOINTS_EXPR_BOOLEAN);
        expr->e.boolean = v;
        return expr;
    } else if (aws_json_value_is_array(node)) {
        struct aws_endpoints_expr *expr = aws_endpoints_expr_new(allocator, AWS_ENDPOINTS_EXPR_ARRAY);
        size_t num_elements = aws_json_get_array_size(node);
        aws_array_list_init_dynamic(&expr->e.array, allocator, num_elements, sizeof(struct aws_endpoints_expr *));
        if (s_init_array_from_json(allocator, node, &expr->e.array, s_on_expr_element)) {
            aws_endpoints_expr_destroy(expr);
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to parse array value type.");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
            return NULL;
        }
        return expr;
    }

    struct aws_endpoints_reference *reference = s_try_parse_reference(allocator, node);
    if (reference) {
        struct aws_endpoints_expr *expr = aws_endpoints_expr_new(allocator, AWS_ENDPOINTS_EXPR_REFERENCE);
        expr->e.reference = reference;
        return expr;
    }

    struct aws_endpoints_function *function = s_try_parse_function(allocator, node);
    if (function) {
        struct aws_endpoints_expr *expr = aws_endpoints_expr_new(allocator, AWS_ENDPOINTS_EXPR_FUNCTION);
        expr->e.function = function;
        return expr;
    }

    /* exhausted all possible value types */
    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to parse value type");
    aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
    return NULL;
}

static struct aws_endpoints_function *s_try_parse_function(
    struct aws_allocator *allocator,
    const struct aws_json_value *node) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(node);

    struct aws_byte_cursor fn_cur;
    struct aws_json_value *fn_node = aws_json_value_get_from_object(node, aws_byte_cursor_from_c_str("fn"));
    if (fn_node == NULL) {
        return NULL;
    }

    if (aws_json_value_get_string(fn_node, &fn_cur)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract fn.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        return NULL;
    }

    struct aws_endpoints_function *function =
        aws_endpoints_function_new(allocator, aws_string_new_from_cursor(allocator, &fn_cur));
    struct aws_json_value *argv_node = aws_json_value_get_from_object(node, aws_byte_cursor_from_c_str("argv"));
    size_t num_args = aws_json_get_array_size(argv_node);
    aws_array_list_init_dynamic(&function->argv, allocator, num_args, sizeof(struct aws_endpoints_value *));

    if (s_init_array_from_json(allocator, argv_node, &function->argv, s_on_expr_element)) {
        aws_endpoints_function_destroy(function);
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to parse argv.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        return NULL;
    }

    return function;
}

static bool s_on_parameter_key(const struct aws_byte_cursor *key, const struct aws_json_value *value, void *user_data) {

    struct member_parser_wrapper *wrapper = user_data;

    /* required fields */
    struct aws_byte_cursor type_cur;
    struct aws_json_value *type_node = aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("type"));
    if (type_node == NULL || aws_json_value_get_string(type_node, &type_cur)) {
        wrapper->all_members_parsed_successfully = false;
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract parameter type.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        return false;
    }

    enum aws_endpoints_parameter_value_type type;
    if (aws_byte_cursor_eq_ignore_case(&type_cur, &s_string_type_cur)) {
        type = AWS_ENDPOINTS_PARAMETER_STRING;
    } else if (aws_byte_cursor_eq_ignore_case(&type_cur, &s_boolean_type_cur)) {
        type = AWS_ENDPOINTS_PARAMETER_BOOLEAN;
    } else {
        wrapper->all_members_parsed_successfully = false;
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Unexpected type for parameter.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        return false;
    }

    struct aws_byte_cursor documentation_cur;
    struct aws_json_value *documentation_node =
        aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("documentation"));
    if (documentation_node == NULL || aws_json_value_get_string(documentation_node, &documentation_cur)) {
        wrapper->all_members_parsed_successfully = false;
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract parameter documentation.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        return false;
    }

    struct aws_endpoints_parameter *parameter = aws_endpoints_parameter_new(
        wrapper->allocator, type, aws_string_new_from_cursor(wrapper->allocator, &documentation_cur));

    /* optional fields */
    parameter->built_in = NULL;
    struct aws_byte_cursor built_in_cur;
    struct aws_json_value *built_in_node = aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("builtIn"));
    if (built_in_node != NULL && !aws_json_value_get_string(built_in_node, &built_in_cur)) {
        parameter->built_in = aws_string_new_from_cursor(wrapper->allocator, &built_in_cur);
    }

    parameter->is_required = false;
    struct aws_json_value *required_node =
        aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("required"));
    if (required_node != NULL) {
        aws_json_value_get_boolean(required_node, &parameter->is_required);
    }

    struct aws_json_value *default_node = aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("default"));
    if (default_node != NULL) {
        if (type == AWS_ENDPOINTS_PARAMETER_STRING) {
            struct aws_byte_cursor default_cur;
            if (aws_json_value_get_string(default_node, &default_cur)) {
                aws_endpoints_parameter_destroy(parameter);
                wrapper->all_members_parsed_successfully = false;
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Unexpected type for default parameter value.");
                aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
                return false;
            }
            parameter->default_value.string = aws_string_new_from_cursor(wrapper->allocator, &default_cur);
        } else if (type == AWS_ENDPOINTS_PARAMETER_BOOLEAN) {
            if (aws_json_value_get_boolean(default_node, &parameter->default_value.boolean)) {
                aws_endpoints_parameter_destroy(parameter);
                wrapper->all_members_parsed_successfully = false;
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Unexpected type for default parameter value.");
                aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
                return false;
            }
        }
    }

    struct aws_json_value *deprecated_node =
        aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("deprecated"));
    if (deprecated_node != NULL) {

        struct aws_byte_cursor deprecated_message_cur;
        struct aws_json_value *deprecated_message_node =
            aws_json_value_get_from_object(deprecated_node, aws_byte_cursor_from_c_str("message"));
        if (deprecated_message_node != NULL &&
            aws_json_value_get_string(deprecated_message_node, &deprecated_message_cur)) {
            aws_endpoints_parameter_destroy(parameter);
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Unexpected value for deprecated message.");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
            return false;
        }
        parameter->deprecated_message = aws_string_new_from_cursor(wrapper->allocator, &deprecated_message_cur);

        struct aws_byte_cursor deprecated_since_cur;
        struct aws_json_value *deprecated_since_node =
            aws_json_value_get_from_object(deprecated_node, aws_byte_cursor_from_c_str("since"));
        if (deprecated_since_node != NULL && aws_json_value_get_string(deprecated_since_node, &deprecated_since_cur)) {
            aws_endpoints_parameter_destroy(parameter);
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Unexpected value for deprecated since.");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
            return false;
        }
        parameter->deprecated_since = aws_string_new_from_cursor(wrapper->allocator, &deprecated_since_cur);
    } else {
        parameter->is_deprecated = false;
        parameter->deprecated_message = NULL;
        parameter->deprecated_since = NULL;
    }

    aws_hash_table_put(wrapper->table, aws_string_new_from_cursor(wrapper->allocator, key), parameter, NULL);
    wrapper->all_members_parsed_successfully = true;
    return true;
}

static bool s_on_condition_element(size_t idx, const struct aws_json_value *condition_node, void *user_data) {
    struct array_parser_wrapper *wrapper = user_data;

    struct aws_endpoints_function *function = s_try_parse_function(wrapper->allocator, condition_node);
    if (function == NULL) {
        wrapper->all_elements_parsed_successfully = false;
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to parse condition function.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        return false;
    }

    struct aws_endpoints_condition *condition = aws_endpoints_condition_new(wrapper->allocator, function);

    struct aws_json_value *assign_node =
        aws_json_value_get_from_object(condition_node, aws_byte_cursor_from_c_str("assign"));
    if (assign_node != NULL) {
        struct aws_byte_cursor cur;
        aws_json_value_get_string(assign_node, &cur);
        condition->assign = aws_string_new_from_cursor(wrapper->allocator, &cur);
    }

    aws_array_list_push_back(wrapper->array, &condition);
    return true;
}

static bool s_on_header_element(size_t idx, const struct aws_json_value *value, void *user_data) {
    struct array_parser_wrapper *wrapper = user_data;
    struct aws_byte_cursor cur;
    aws_json_value_get_string(value, &cur);

    struct aws_string *string = aws_string_new_from_cursor(wrapper->allocator, &cur);
    aws_array_list_push_back(wrapper->array, &string);
    return true;
}

static bool s_on_headers_key(const struct aws_byte_cursor *key, const struct aws_json_value *value, void *user_data) {
    struct member_parser_wrapper *wrapper = user_data;

    if (aws_json_value_is_array(value)) {
        size_t num_elements = aws_json_get_array_size(value);
        struct aws_array_list *headers = aws_mem_acquire(wrapper->allocator, sizeof(struct aws_array_list));
        AWS_ZERO_STRUCT(*headers);
        aws_array_list_init_dynamic(headers, wrapper->allocator, num_elements, sizeof(struct aws_string *));
        if (s_init_array_from_json(wrapper->allocator, value, headers, s_on_header_element)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract url.");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
            return false;
        }

        aws_hash_table_put(wrapper->table, aws_string_new_from_cursor(wrapper->allocator, key), headers, NULL);
    }

    return true;
}

static struct aws_endpoints_rule_data_endpoint *s_parse_endpoints_rule_data_endpoint(
    struct aws_allocator *allocator,
    const struct aws_json_value *rule_node) {

    struct aws_endpoints_rule_data_endpoint *data_rule = aws_endpoints_rule_data_endpoint_new(allocator);

    struct aws_json_value *url_node = aws_json_value_get_from_object(rule_node, aws_byte_cursor_from_c_str("url"));
    if (aws_json_value_is_string(url_node)) {
        struct aws_byte_cursor url_cur;
        if (aws_json_value_get_string(url_node, &url_cur)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract url.");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
            goto error_cleanup;
        }

        data_rule->url_type = AWS_ENDPOINTS_URL_TEMPLATE;
        data_rule->url.template = aws_string_new_from_cursor(allocator, &url_cur);
        return data_rule;
    } else {
        struct aws_endpoints_reference *reference = s_try_parse_reference(allocator, url_node);
        if (reference != NULL) {
            data_rule->url_type = AWS_ENDPOINTS_URL_REFERENCE;
            data_rule->url.reference = reference;
        }

        struct aws_endpoints_function *function = s_try_parse_function(allocator, url_node);
        if (function != NULL) {
            data_rule->url_type = AWS_ENDPOINTS_URL_FUNCTION;
            data_rule->url.function = function;
        }
    }

    struct aws_json_value *properties_node =
        aws_json_value_get_from_object(rule_node, aws_byte_cursor_from_c_str("properties"));
    if (properties_node != NULL) {
        struct aws_byte_cursor properties_cur;
        if (aws_json_value_get_string(properties_node, &properties_cur)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract properties.");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
            goto error_cleanup;
        }

        data_rule->properties = aws_string_new_from_cursor(allocator, &properties_cur);
    }

    struct aws_json_value *headers_node =
        aws_json_value_get_from_object(rule_node, aws_byte_cursor_from_c_str("headers"));
    if (headers_node != NULL) {
        data_rule->headers = aws_mem_acquire(allocator, sizeof(struct aws_hash_table *));
        AWS_ZERO_STRUCT(*data_rule->headers);
        aws_hash_table_init(
            data_rule->headers,
            allocator,
            20,
            aws_hash_c_string,
            aws_hash_callback_c_str_eq,
            aws_hash_callback_string_destroy,
            aws_hash_callback_headers_destroy);

        struct aws_json_value *headers_node =
            aws_json_value_get_from_object(rule_node, aws_byte_cursor_from_c_str("headers"));
        if (s_init_members_from_json(allocator, headers_node, data_rule->headers, s_on_headers_key)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract parameters.");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
            goto error_cleanup;
        }
    }

error_cleanup:
    aws_endpoints_rule_data_endpoint_destroy(data_rule);
    return NULL;
}

static struct aws_endpoints_rule_data_error *s_parse_endpoints_rule_data_error(
    struct aws_allocator *allocator,
    const struct aws_json_value *error_node) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(error_node);

    if (aws_json_value_is_string(error_node)) {
        struct aws_byte_cursor error_cur;
        if (aws_json_value_get_string(error_node, &error_cur)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract rule type.");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
            return NULL;
        }
        struct aws_endpoints_rule_data_error *data_rule = aws_endpoints_rule_data_error_new(allocator);
        data_rule->error_type = AWS_ENDPOINTS_ERROR_TEMPLATE;
        data_rule->error.template = aws_string_new_from_cursor(allocator, &error_cur);
        return data_rule;
    }

    struct aws_endpoints_reference *reference = s_try_parse_reference(allocator, error_node);
    if (reference != NULL) {
        struct aws_endpoints_rule_data_error *data_rule = aws_endpoints_rule_data_error_new(allocator);
        data_rule->error_type = AWS_ENDPOINTS_ERROR_REFERENCE;
        data_rule->error.reference = reference;
        return data_rule;
    }

    struct aws_endpoints_function *function = s_try_parse_function(allocator, error_node);
    if (function != NULL) {
        struct aws_endpoints_rule_data_error *data_rule = aws_endpoints_rule_data_error_new(allocator);
        data_rule->error_type = AWS_ENDPOINTS_ERROR_FUNCTION;
        data_rule->error.function = function;
        return data_rule;
    }

    AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to parse error rule.");
    aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
    return NULL;
}

static bool s_on_rule_element(size_t idx, const struct aws_json_value *value, void *user_data);

static struct aws_endpoints_rule_data_tree *s_parse_endpoints_rule_data_tree(
    struct aws_allocator *allocator,
    const struct aws_json_value *rule_node) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(rule_node);

    struct aws_endpoints_rule_data_tree *rule_data = aws_endpoints_rule_data_tree_new(allocator);
    struct aws_json_value *rules_node = aws_json_value_get_from_object(rule_node, aws_byte_cursor_from_c_str("rules"));
    size_t num_rules = aws_json_get_array_size(rules_node);
    aws_array_list_init_dynamic(&rule_data->rules, allocator, num_rules, sizeof(void *));
    if (s_init_array_from_json(allocator, rules_node, &rule_data->rules, s_on_rule_element)) {
        aws_endpoints_rule_data_tree_destroy(rule_data);
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to parse rules.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        return NULL;
    }

    return rule_data;
}

static bool s_on_rule_element(size_t idx, const struct aws_json_value *value, void *user_data) {
    struct array_parser_wrapper *wrapper = user_data;

    /* Required fields */
    struct aws_byte_cursor type_cur;
    struct aws_json_value *type_node = aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("type"));
    if (type_node == NULL || aws_json_value_get_string(type_node, &type_cur)) {
        wrapper->all_elements_parsed_successfully = false;
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract rule type.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        return false;
    }

    enum aws_endpoints_rule_type type;
    if (aws_byte_cursor_eq_ignore_case(&type_cur, &s_endpoint_type_cur)) {
        type = AWS_ENDPOINTS_RULE_ENDPOINT;
    } else if (aws_byte_cursor_eq_ignore_case(&type_cur, &s_error_type_cur)) {
        type = AWS_ENDPOINTS_RULE_ERROR;
    } else if (aws_byte_cursor_eq_ignore_case(&type_cur, &s_tree_type_cur)) {
        type = AWS_ENDPOINTS_RULE_TREE;
    } else {
        AWS_FATAL_ASSERT(false);
    }

    struct aws_endpoints_rule *rule = aws_endpoints_rule_new(wrapper->allocator, type);
    struct aws_json_value *conditions_node =
        aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("conditions"));
    size_t num_conditions = aws_json_get_array_size(conditions_node);
    aws_array_list_init_dynamic(
        &rule->conditions, wrapper->allocator, num_conditions, sizeof(struct aws_endpoints_condition *));

    if (s_init_array_from_json(wrapper->allocator, conditions_node, &rule->conditions, s_on_condition_element)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract conditions.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        goto error_cleanup;
    }

    switch (type) {
        case AWS_ENDPOINTS_RULE_ENDPOINT: {
            struct aws_json_value *endpoint_node =
                aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("endpoint"));
            struct aws_endpoints_rule_data_endpoint *rule_data =
                s_parse_endpoints_rule_data_endpoint(wrapper->allocator, endpoint_node);
            if (rule_data == NULL) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract endpoint rule data.");
                aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
                goto error_cleanup;
            }
            rule->rule_data.endpoint = rule_data;
            break;
        }
        case AWS_ENDPOINTS_RULE_ERROR: {
            struct aws_json_value *error_node =
                aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("error"));
            struct aws_endpoints_rule_data_error *rule_data =
                s_parse_endpoints_rule_data_error(wrapper->allocator, error_node);
            if (rule_data == NULL) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract error rule data.");
                aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
                goto error_cleanup;
            }
            rule->rule_data.error = rule_data;
            break;
        }
        case AWS_ENDPOINTS_RULE_TREE: {
            struct aws_endpoints_rule_data_tree *rule_data =
                s_parse_endpoints_rule_data_tree(wrapper->allocator, value);
            if (rule_data == NULL) {
                AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract tree rule data.");
                aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
                goto error_cleanup;
            }
            rule->rule_data.tree = rule_data;
            break;
        }
        default:
            AWS_FATAL_ASSERT(false);
    }

    /* Optional fields */
    struct aws_json_value *documentation_node =
        aws_json_value_get_from_object(value, aws_byte_cursor_from_c_str("documentation"));
    if (documentation_node != NULL) {
        struct aws_byte_cursor documentation_cur;
        if (aws_json_value_get_string(documentation_node, &documentation_cur)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract parameter documentation.");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
            goto error_cleanup;
        }
        rule->documentation = aws_string_new_from_cursor(wrapper->allocator, &documentation_cur);
    }

    aws_array_list_push_back(wrapper->array, &rule);

    return true;

error_cleanup:
    wrapper->all_elements_parsed_successfully = false;
    aws_endpoints_rule_destroy(rule);
    return false;
}

static int s_init_ruleset_from_json(
    struct aws_allocator *allocator,
    struct aws_endpoints_ruleset *ruleset,
    const struct aws_byte_cursor *json) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(ruleset);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(json));

    /*
     * TODO: this could be more efficient. currently user allocates mem for json
     * string, we create a copy in json parser and then string fields create
     * another copy.
     */

    struct aws_json_value *root = aws_json_value_new_from_string(allocator, *json);

    if (root == NULL) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to parse provided string as json.");
        return aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
    }

    struct aws_byte_cursor version_cur;
    struct aws_json_value *version_node = aws_json_value_get_from_object(root, aws_byte_cursor_from_c_str("version"));
    if (version_node == NULL || aws_json_value_get_string(version_node, &version_cur)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract version.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_UNSUPPORTED_RULESET);
        goto error_cleanup;
    }

#ifdef VERSION_CHECK /* TODO: samples are currently inconsistent with versions. skip check for now */
    if (aws_byte_cursor_eq_c_str(&version_cur, "1.0")) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Unsupported ruleset version.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_UNSUPPORTED_RULESET);
        goto error_cleanup;
    }
#endif

    ruleset->version = aws_string_new_from_cursor(allocator, &version_cur);

    struct aws_byte_cursor service_id_cur;
    struct aws_json_value *service_id_node =
        aws_json_value_get_from_object(root, aws_byte_cursor_from_c_str("serviceId"));

    if (service_id_node != NULL) {
        if (aws_json_value_get_string(service_id_node, &service_id_cur)) {
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract serviceId.");
            aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_UNSUPPORTED_RULESET);
            goto error_cleanup;
        }
        ruleset->service_id = aws_string_new_from_cursor(allocator, &service_id_cur);
    }

    ruleset->parameters = aws_mem_acquire(allocator, sizeof(struct aws_hash_table));
    AWS_ZERO_STRUCT(*ruleset->parameters);
    aws_hash_table_init(
        ruleset->parameters,
        allocator,
        20,
        aws_hash_c_string,
        aws_hash_callback_c_str_eq,
        aws_hash_callback_string_destroy,
        aws_hash_callback_endpoints_parameter_destroy);

    struct aws_json_value *parameters_node =
        aws_json_value_get_from_object(root, aws_byte_cursor_from_c_str("parameters"));
    if (s_init_members_from_json(allocator, parameters_node, ruleset->parameters, s_on_parameter_key)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract parameters.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        goto error_cleanup;
    }

    struct aws_json_value *rules_node = aws_json_value_get_from_object(root, aws_byte_cursor_from_c_str("rules"));
    if (!aws_json_value_is_array(rules_node)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Unexpected type for rules node.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        goto error_cleanup;
    }
    size_t num_rules = aws_json_get_array_size(rules_node);
    aws_array_list_init_dynamic(&ruleset->rules, allocator, num_rules, sizeof(struct aws_endpoints_rule *));
    if (s_init_array_from_json(allocator, rules_node, &ruleset->rules, s_on_rule_element)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Failed to extract rules.");
        aws_raise_error(AWS_ERROR_SDKUTILS_ENDPOINTS_PARSE_FAILED);
        goto error_cleanup;
    }

    aws_json_value_destroy(root);
    return AWS_OP_SUCCESS;

error_cleanup:
    aws_json_value_destroy(root);
    return AWS_OP_ERR;
}

static void s_endpoints_ruleset_destroy(void *data) {
    struct aws_endpoints_ruleset *ruleset = data;

    aws_string_destroy(ruleset->version);
    aws_string_destroy(ruleset->service_id);

    if (ruleset->parameters) {
        aws_hash_table_clean_up(ruleset->parameters);
        aws_mem_release(ruleset->allocator, ruleset->parameters);
    }

    aws_array_list_deep_cleanup(&ruleset->rules, s_on_rule_array_element_destroy);

    aws_mem_release(ruleset->allocator, ruleset);
}

struct aws_endpoints_ruleset *aws_endpoints_ruleset_new_from_string(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *ruleset_cur) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(aws_byte_cursor_is_valid(ruleset_cur));

    struct aws_endpoints_ruleset *ruleset = aws_mem_acquire(allocator, sizeof(struct aws_endpoints_ruleset));
    AWS_ZERO_STRUCT(*ruleset);
    ruleset->allocator = allocator;
    aws_ref_count_init(&ruleset->ref_count, ruleset, s_endpoints_ruleset_destroy);

    if (s_init_ruleset_from_json(allocator, ruleset, ruleset_cur)) {
        s_endpoints_ruleset_destroy(ruleset);
        return NULL;
    }

    return ruleset;
}

void aws_endpoints_ruleset_acquire(struct aws_endpoints_ruleset *ruleset) {
    AWS_FATAL_PRECONDITION(ruleset);
    aws_ref_count_acquire(&ruleset->ref_count);
}

void aws_endpoints_ruleset_release(struct aws_endpoints_ruleset *ruleset) {
    if (ruleset) {
        aws_ref_count_release(&ruleset->ref_count);
    }
}

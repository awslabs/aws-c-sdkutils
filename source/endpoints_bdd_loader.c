/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_buf.h>
#include <aws/common/encoding.h>
#include <aws/common/hash_table.h>
#include <aws/sdkutils/endpoints_bdd_engine.h>
#include <aws/sdkutils/partitions.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/sdkutils/private/endpoints_util.h>

#define BDD_MAGIC_NUMBER 0x45504452 /* "EPDR" */

enum bdd_opcode {
    BDD_OP_PARAM_STRING = 0x01,
    BDD_OP_PARAM_BOOL = 0x02,
    BDD_OP_PARAM_STRING_ARRAY = 0x03,
    BDD_OP_CONDITION = 0x10,
    BDD_OP_RESULT_ENDPOINT = 0x20,
    BDD_OP_RESULT_ERROR = 0x21,
};

/* Forward declaration */
static void s_endpoints_bdd_engine_destroy(void *data);

static void s_on_condition_array_element_clean_up(void *element) {
    struct aws_endpoints_condition *condition = element;
    aws_endpoints_condition_clean_up(condition);
}

static void s_on_resutls_array_element_clean_up(void *element) {
    struct aws_endpoints_bdd_result *result = element;
    switch (result->type) {
        case AWS_ENDPOINTS_RESOLVED_ENDPOINT:
            aws_endpoints_rule_data_endpoint_clean_up(&result->data.endpoint);
            break;
        case AWS_ENDPOINTS_RESOLVED_ERROR:
            aws_endpoints_rule_data_error_clean_up(&result->data.error);
            break;
        default:
            AWS_FATAL_ASSERT(false);
    }
}

static int s_validate_magic_number(struct aws_byte_cursor *cursor) {
    uint32_t magic;
    if (!aws_byte_cursor_read_le32(cursor, &magic)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (magic != BDD_MAGIC_NUMBER) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    return AWS_OP_SUCCESS;
}

static int s_load_string_table(struct aws_byte_cursor *cursor, struct aws_byte_cursor *out_blob) {
    uint32_t blob_size;
    if (!aws_byte_cursor_read_le32(cursor, &blob_size)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (cursor->len < blob_size) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out_blob = aws_byte_cursor_from_array(cursor->ptr, blob_size);
    aws_byte_cursor_advance(cursor, blob_size);
    return AWS_OP_SUCCESS;
}

static int s_read_string_ref(struct aws_byte_cursor *cursor, struct aws_byte_cursor blob, struct aws_byte_cursor *out) {
    uint16_t offset, length;
    if (!aws_byte_cursor_read_le16(cursor, &offset) || !aws_byte_cursor_read_le16(cursor, &length)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if ((size_t)offset + length > blob.len) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out = aws_byte_cursor_from_array(blob.ptr + offset, length);
    return AWS_OP_SUCCESS;
}

static void s_callback_endpoints_parameter_destroy(void *data) {
    struct aws_endpoints_parameter *parameter = data;
    aws_endpoints_parameter_destroy(parameter);
}

static int s_parse_one_parameter(
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_endpoints_parameter *param) {

    uint8_t opcode;
    if (!aws_byte_cursor_read_u8(cursor, &opcode)) {
        return AWS_OP_ERR;
    }

    switch (opcode) {
        case BDD_OP_PARAM_STRING:
            param->type = AWS_ENDPOINTS_PARAMETER_STRING;
            break;
        case BDD_OP_PARAM_BOOL:
            param->type = AWS_ENDPOINTS_PARAMETER_BOOLEAN;
            break;
        case BDD_OP_PARAM_STRING_ARRAY:
            param->type = AWS_ENDPOINTS_PARAMETER_STRING_ARRAY;
            break;
        default:
            return AWS_OP_ERR;
    }

    if (s_read_string_ref(cursor, blob, &param->name)) {
        return AWS_OP_ERR;
    }

    uint8_t has_default;
    if (!aws_byte_cursor_read_u8(cursor, &has_default)) {
        return AWS_OP_ERR;
    }
    param->has_default_value = (has_default != 0);

    if (has_default) {
        if (param->type == AWS_ENDPOINTS_PARAMETER_STRING || param->type == AWS_ENDPOINTS_PARAMETER_STRING_ARRAY) {
            struct aws_byte_cursor default_cur;
            if (s_read_string_ref(cursor, blob, &default_cur)) {
                return AWS_OP_ERR;
            }
            param->default_value.type = AWS_ENDPOINTS_VALUE_STRING;
            param->default_value.v.owning_cursor_string.cur = default_cur;
            param->default_value.is_ref = true;
        } else {
            uint8_t bool_val;
            if (!aws_byte_cursor_read_u8(cursor, &bool_val)) {
                return AWS_OP_ERR;
            }
            param->default_value.type = AWS_ENDPOINTS_VALUE_BOOLEAN;
            param->default_value.v.boolean = (bool_val != 0);
        }
    }

    uint8_t is_required;
    if (!aws_byte_cursor_read_u8(cursor, &is_required)) {
        return AWS_OP_ERR;
    }
    param->is_required = (is_required != 0);

    uint8_t has_builtin;
    if (!aws_byte_cursor_read_u8(cursor, &has_builtin)) {
        return AWS_OP_ERR;
    }
    if (has_builtin) {
        if (s_read_string_ref(cursor, blob, &param->built_in)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_load_parameters(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_hash_table *out_parameters) {

    uint16_t count;
    if (!aws_byte_cursor_read_le16(cursor, &count)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (aws_hash_table_init(
            out_parameters,
            allocator,
            count,
            aws_hash_byte_cursor_ptr,
            aws_endpoints_byte_cursor_eq,
            NULL,
            s_callback_endpoints_parameter_destroy)) {
        return AWS_OP_ERR;
    }

    for (uint16_t i = 0; i < count; ++i) {
        struct aws_endpoints_parameter *param = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_parameter));
        if (!param) {
            goto error;
        }
        param->allocator = allocator;

        if (s_parse_one_parameter(cursor, blob, param) ||
            aws_hash_table_put(out_parameters, &param->name, param, NULL)) {
            aws_mem_release(allocator, param);
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    aws_hash_table_clean_up(out_parameters);
    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}

static int s_decode_value(
    struct aws_endpoints_bdd_engine *engine,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_endpoints_expr *out_expr);

static int s_decode_value_to_ref(
    struct aws_endpoints_bdd_engine *engine,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    uint16_t *out_ref) {

    struct aws_endpoints_expr *expr = &engine->expr_ptr[engine->expr_len];
    *out_ref = engine->expr_len++;

    if (s_decode_value(engine, cursor, blob, expr)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/* todo: this can be moved into compiler */
static bool s_is_template_string(struct aws_byte_cursor cur) {
    for (size_t i = 0; i < cur.len; ++i) {
        if (cur.ptr[i] == '{') {
            return true;
        }
    }
    return false;
}

static int s_decode_value(
    struct aws_endpoints_bdd_engine *engine,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_endpoints_expr *out_expr) {

    uint8_t tag;
    if (!aws_byte_cursor_read_u8(cursor, &tag)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    switch (tag) {
        case 0: /* None */
            out_expr->type = AWS_ENDPOINTS_EXPR_STRING;
            out_expr->e.string = aws_byte_cursor_from_c_str("");
            break;

        case 1: { /* String */
            struct aws_byte_cursor str_cur;
            if (s_read_string_ref(cursor, blob, &str_cur)) {
                return AWS_OP_ERR;
            }
            out_expr->type =
                s_is_template_string(str_cur) ? AWS_ENDPOINTS_EXPR_TEMPLATE_STRING : AWS_ENDPOINTS_EXPR_STRING;
            out_expr->e.string = str_cur;
            break;
        }

        case 2: { /* Boolean */
            uint8_t bool_val;
            if (!aws_byte_cursor_read_u8(cursor, &bool_val)) {
                return AWS_OP_ERR;
            }
            out_expr->type = AWS_ENDPOINTS_EXPR_BOOLEAN;
            out_expr->e.boolean = (bool_val != 0);
            break;
        }

        case 3: { /* Integer */
            int32_t int_val;
            if (!aws_byte_cursor_read_le_i32(cursor, &int_val)) {
                return AWS_OP_ERR;
            }
            out_expr->type = AWS_ENDPOINTS_EXPR_NUMBER;
            out_expr->e.number = (double)int_val;
            break;
        }

        case 4: { /* Reference */
            struct aws_byte_cursor ref_cur;
            if (s_read_string_ref(cursor, blob, &ref_cur)) {
                return AWS_OP_ERR;
            }
            out_expr->type = AWS_ENDPOINTS_EXPR_REFERENCE;
            struct aws_endpoints_reference ref = {.name = ref_cur};

            struct aws_hash_element *element = NULL;
            aws_hash_table_find(&engine->register_map, &ref_cur, &element);
            if (element != NULL) {
                size_t reg_index = (size_t)element->value;
                ref.bdd_ref_idx = reg_index + 1;
            } else {
                ref.bdd_ref_idx = aws_hash_table_get_entry_count(&engine->register_map) + 1;
                aws_hash_table_put(&engine->register_map, &ref_cur, (void *)ref.bdd_ref_idx, NULL);
            }

            out_expr->e.reference = ref;
            break;
        }

        case 5: { /* Function */
            uint8_t fn_type;
            if (!aws_byte_cursor_read_u8(cursor, &fn_type)) {
                return AWS_OP_ERR;
            }

            if (!aws_byte_cursor_read_le16(cursor, &out_expr->e.function.args.argc)) {
                return AWS_OP_ERR;
            }

            out_expr->type = AWS_ENDPOINTS_EXPR_FUNCTION;
            out_expr->e.function.fn = fn_type;

            for (uint16_t i = 0; i < out_expr->e.function.args.argc; ++i) {
                if (s_decode_value_to_ref(engine, cursor, blob, &out_expr->e.function.args.argv[i])) {
                    return AWS_OP_ERR;
                }
            }
            break;
        }

        case 6: { /* Array */
            uint16_t length;
            if (!aws_byte_cursor_read_le16(cursor, &length)) {
                return AWS_OP_ERR;
            }

            out_expr->type = AWS_ENDPOINTS_EXPR_ARRAY;
            out_expr->e.array.len = length;

            for (uint16_t i = 0; i < length; ++i) {
                if (s_decode_value_to_ref(engine, cursor, blob, &out_expr->e.array.ptr[i])) {
                    return AWS_OP_ERR;
                }
            }
            break;
        }

        case 7: { /* Object */
            uint16_t length;
            if (!aws_byte_cursor_read_le16(cursor, &length)) {
                return AWS_OP_ERR;
            }

            out_expr->type = AWS_ENDPOINTS_EXPR_OBJECT;
            if (aws_array_list_init_dynamic(
                    &out_expr->e.object, engine->allocator, length, sizeof(struct aws_endpoints_kv_pair))) {
                return AWS_OP_ERR;
            }

            for (uint16_t i = 0; i < length; ++i) {
                struct aws_byte_cursor key_cur;
                if (s_read_string_ref(cursor, blob, &key_cur)) {
                    return AWS_OP_ERR;
                }

                struct aws_endpoints_kv_pair pair;
                pair.allocator = engine->allocator;
                pair.key = key_cur;

                if (s_decode_value_to_ref(engine, cursor, blob, &pair.expr_ref)) {
                    return AWS_OP_ERR;
                }
            }
            break;
        }

        default:
            AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Unknown value tag: %d", (int)tag);
            return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_parse_one_condition(
    struct aws_endpoints_bdd_engine *engine,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_endpoints_condition *cond) {

    uint8_t opcode;
    if (!aws_byte_cursor_read_u8(cursor, &opcode) || opcode != BDD_OP_CONDITION) {
        return AWS_OP_ERR;
    }

    struct aws_endpoints_expr *expr = &engine->expr_ptr[engine->expr_len];
    expr->type = AWS_ENDPOINTS_EXPR_FUNCTION;
    expr->e.function.allocator = engine->allocator;
    uint8_t fn_type;
    if (!aws_byte_cursor_read_u8(cursor, &fn_type)) {
        return AWS_OP_ERR;
    }
    expr->e.function.fn = fn_type;

    if (!aws_byte_cursor_read_le16(cursor, &expr->e.function.args.argc)) {
        return AWS_OP_ERR;
    }

    cond->expr_ref = engine->expr_len++;

    for (uint16_t i = 0; i < expr->e.function.args.argc; ++i) {
        if (s_decode_value_to_ref(engine, cursor, blob, &expr->e.function.args.argv[i])) {
            goto on_error;
        }
    }

    uint8_t has_assign;
    if (!aws_byte_cursor_read_u8(cursor, &has_assign)) {
        goto on_error;
    }

    if (has_assign) {
        if (s_read_string_ref(cursor, blob, &cond->assign)) {
            goto on_error;
        }

        struct aws_hash_element *element = NULL;
        aws_hash_table_find(&engine->register_map, &cond->assign, &element);
        if (element != NULL) {
            size_t reg_index = (size_t)element->value + 1;
            cond->assign_idx = reg_index;
        } else {
            cond->assign_idx = aws_hash_table_get_entry_count(&engine->register_map) + 1;
            aws_hash_table_put(&engine->register_map, &cond->assign, (void *)cond->assign_idx, NULL);
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_expr_clean_up(expr);
    return AWS_OP_ERR;
}

static int s_load_conditions(
    struct aws_endpoints_bdd_engine *engine,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_array_list *out_conditions,
    struct aws_endpoints_condition **out_conditions_ptr) {

    uint16_t count;
    if (!aws_byte_cursor_read_le16(cursor, &count)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_endpoints_condition *conditions =
        aws_mem_calloc(engine->allocator, count, sizeof(struct aws_endpoints_condition));

    for (uint16_t i = 0; i < count; ++i) {
        if (s_parse_one_condition(engine, cursor, blob, &conditions[i])) {
            goto error;
        }
    }

    aws_array_list_init_static_from_initialized(
        out_conditions, conditions, count, sizeof(struct aws_endpoints_condition));

    *out_conditions_ptr = conditions;

    return AWS_OP_SUCCESS;

error:
    aws_mem_release(engine->allocator, conditions);
    aws_array_list_deep_clean_up(out_conditions, s_on_condition_array_element_clean_up);
    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}

static void s_callback_headers_destroy(void *data) {
    struct aws_array_list *array = data;
    struct aws_allocator *alloc = array->alloc;
    aws_array_list_clean_up(array);
    aws_mem_release(alloc, array);
}

static int s_load_results(
    struct aws_endpoints_bdd_engine *engine,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_array_list *out_results) {

    uint16_t count;
    if (!aws_byte_cursor_read_le16(cursor, &count)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (aws_array_list_init_dynamic(
            out_results, engine->allocator, count + 1, sizeof(struct aws_endpoints_bdd_result))) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Insert NoMatchRule as results[0] */
    struct aws_endpoints_expr *expr = &engine->expr_ptr[engine->expr_len];
    expr->type = AWS_ENDPOINTS_EXPR_STRING;
    expr->e.string = aws_byte_cursor_from_c_str("No matching rule");

    struct aws_endpoints_bdd_result no_match;
    AWS_ZERO_STRUCT(no_match);
    no_match.type = AWS_ENDPOINTS_RESOLVED_ERROR;
    no_match.data.error.error_expr_ref = engine->expr_len++;

    if (aws_array_list_push_back(out_results, &no_match)) {
        goto error;
    }

    for (uint16_t i = 0; i < count; ++i) {
        uint8_t opcode;
        if (!aws_byte_cursor_read_u8(cursor, &opcode)) {
            goto error;
        }

        struct aws_endpoints_bdd_result result;
        AWS_ZERO_STRUCT(result);

        if (opcode == BDD_OP_RESULT_ENDPOINT) {
            result.type = AWS_ENDPOINTS_RESOLVED_ENDPOINT;

            if (s_decode_value_to_ref(engine, cursor, blob, &result.data.endpoint.url_expr_ref)) {
                goto error;
            }

            struct aws_byte_cursor props;
            if (s_read_string_ref(cursor, blob, &props)) {
                goto error;
            }

            result.data.endpoint.properties = aws_byte_buf_from_array(props.ptr, props.len);

            uint16_t headers_count;
            if (!aws_byte_cursor_read_le16(cursor, &headers_count)) {
                goto error;
            }

            aws_hash_table_init(
                &result.data.endpoint.headers,
                engine->allocator,
                headers_count,
                aws_hash_string,
                aws_hash_callback_string_eq,
                aws_hash_callback_string_destroy,
                s_callback_headers_destroy);

            for (uint16_t header_i = 0; header_i < headers_count; ++header_i) {
                struct aws_byte_cursor header_name;
                if (s_read_string_ref(cursor, blob, &header_name)) {
                    aws_hash_table_clean_up(&result.data.endpoint.headers);
                    goto error;
                }

                uint16_t value_count;
                if (!aws_byte_cursor_read_le16(cursor, &value_count)) {
                    aws_hash_table_clean_up(&result.data.endpoint.headers);
                    goto error;
                }

                struct aws_array_list *values = aws_mem_calloc(engine->allocator, 1, sizeof(struct aws_array_list));
                aws_array_list_init_dynamic(values, engine->allocator, value_count, sizeof(uint16_t));
                for (uint16_t value_i = 0; value_i < value_count; ++value_i) {
                    uint16_t expr_ref;
                    if (s_decode_value_to_ref(engine, cursor, blob, &expr_ref)) {
                        aws_hash_table_clean_up(&result.data.endpoint.headers);
                        aws_mem_release(engine->allocator, values);
                        goto error;
                    }
                    aws_array_list_push_back(values, &expr_ref);
                }

                aws_hash_table_put(
                    &result.data.endpoint.headers,
                    aws_string_new_from_cursor(engine->allocator, &header_name),
                    values,
                    NULL);
            }

        } else if (opcode == BDD_OP_RESULT_ERROR) {
            result.type = AWS_ENDPOINTS_RESOLVED_ERROR;

            if (s_decode_value_to_ref(engine, cursor, blob, &result.data.error.error_expr_ref)) {
                goto error;
            }

        } else {
            goto error;
        }

        if (aws_array_list_push_back(out_results, &result)) {
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    aws_array_list_clean_up(out_results);
    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}

static int s_load_nodes(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    int32_t *out_root_ref,
    struct aws_array_list *out_nodes) {

    if (!aws_byte_cursor_read_le_i32(cursor, out_root_ref)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    uint32_t node_count;
    if (!aws_byte_cursor_read_le32(cursor, &node_count)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    uint16_t data_length;
    if (!aws_byte_cursor_read_le16(cursor, &data_length)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (cursor->len < data_length) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    uint8_t padding = 0;
    if (!aws_byte_cursor_read_u8(cursor, &padding)) {
        return AWS_OP_ERR;
    }
    aws_byte_cursor_advance(cursor, padding);

    struct aws_byte_cursor data = aws_byte_cursor_advance(cursor, data_length);

    size_t expected_size = node_count * 12; /* 3 int32s per node */
    if (data.len != expected_size) {
        return AWS_OP_ERR;
    }

    if (aws_is_big_endian()) {
        if (aws_array_list_init_dynamic(out_nodes, allocator, node_count, sizeof(struct aws_endpoints_bdd_node))) {
            return AWS_OP_ERR;
        }
        for (uint32_t i = 0; i < node_count; ++i) {
            struct aws_endpoints_bdd_node node;
            if (!aws_byte_cursor_read_le_i32(&data, &node.condition_index) ||
                !aws_byte_cursor_read_le_i32(&data, &node.high_ref) ||
                !aws_byte_cursor_read_le_i32(&data, &node.low_ref)) {
                aws_array_list_clean_up(out_nodes);
                return AWS_OP_ERR;
            }
            aws_array_list_push_back(out_nodes, &node);
        }

    } else {
        aws_array_list_init_static_from_initialized(
            out_nodes, data.ptr, node_count, sizeof(struct aws_endpoints_bdd_node));

        aws_byte_cursor_advance(cursor, expected_size);
    }

    return AWS_OP_SUCCESS;
}

struct aws_endpoints_bdd_engine *aws_endpoints_bdd_engine_new_from_bytecode(
    struct aws_allocator *allocator,
    struct aws_byte_cursor bytecode,
    struct aws_partitions_config *partitions_config) {

    AWS_PRECONDITION(allocator);

    struct aws_endpoints_bdd_engine *engine = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_bdd_engine));
    if (!engine) {
        return NULL;
    }

    engine->allocator = allocator;
    aws_ref_count_init(&engine->ref_count, engine, s_endpoints_bdd_engine_destroy);
    engine->partitions_config = aws_partitions_config_acquire(partitions_config);

    if (s_validate_magic_number(&bytecode)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to validate magic number");
        goto error;
    }

    if (aws_hash_table_init(
            &engine->register_map,
            allocator,
            s_max_regs,
            aws_hash_byte_cursor_ptr,
            aws_endpoints_byte_cursor_eq,
            NULL,
            NULL)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to create reg map");
        goto error;
    }

    if (s_load_string_table(&bytecode, &engine->string_blob)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load string table");
        goto error;
    }

    struct aws_byte_cursor version_cur;
    if (s_read_string_ref(&bytecode, engine->string_blob, &version_cur)) {
        goto error;
    }
    engine->version = version_cur;

    if (s_load_parameters(allocator, &bytecode, engine->string_blob, &engine->parameters)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load parameters");
        goto error;
    }

    size_t param_count = 0;
    for (struct aws_hash_iter iter = aws_hash_iter_begin(&engine->parameters); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {

        struct aws_endpoints_parameter *value = (struct aws_endpoints_parameter *)iter.element.value;

        struct aws_hash_element *element = NULL;
        aws_hash_table_find(&engine->register_map, &value->name, &element);

        if (element == NULL) {
            aws_hash_table_put(&engine->register_map, &value->name, (void *)param_count, NULL);
            param_count++;
        }
    }

    if (s_load_conditions(engine, &bytecode, engine->string_blob, &engine->conditions, &engine->conditions_ptr)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load conditions");
        goto error;
    }

    if (s_load_results(engine, &bytecode, engine->string_blob, &engine->results)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load results");
        goto error;
    }

    if (s_load_nodes(allocator, &bytecode, &engine->root_ref, &engine->nodes)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load nodes");
        goto error;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE,
        "BDD engine loaded: %d params, %d conditions, %d results, %d nodes",
        (int)aws_hash_table_get_entry_count(&engine->parameters),
        (int)aws_array_list_length(&engine->conditions),
        (int)aws_array_list_length(&engine->results),
        (int)aws_array_list_length(&engine->nodes));

    return engine;

error:
    s_endpoints_bdd_engine_destroy(engine);
    return NULL;
}

static void s_endpoints_bdd_engine_destroy(void *data) {
    if (data == NULL) {
        return;
    }

    struct aws_endpoints_bdd_engine *engine = data;

    if (engine->partitions_config) {
        aws_partitions_config_release(engine->partitions_config);
    }

    aws_hash_table_clean_up(&engine->parameters);
    aws_hash_table_clean_up(&engine->register_map);
    aws_array_list_deep_clean_up(&engine->conditions, s_on_condition_array_element_clean_up);
    aws_mem_release(engine->allocator, engine->conditions_ptr);
    aws_array_list_deep_clean_up(&engine->results, s_on_resutls_array_element_clean_up);
    aws_array_list_clean_up(&engine->results);
    aws_array_list_clean_up(&engine->nodes);

    aws_mem_release(engine->allocator, engine);
}

struct aws_endpoints_bdd_engine *aws_endpoints_bdd_engine_acquire(struct aws_endpoints_bdd_engine *engine) {
    AWS_PRECONDITION(engine);
    if (engine) {
        aws_ref_count_acquire(&engine->ref_count);
    }
    return engine;
}

struct aws_endpoints_bdd_engine *aws_endpoints_bdd_engine_release(struct aws_endpoints_bdd_engine *engine) {
    if (engine) {
        aws_ref_count_release(&engine->ref_count);
    }
    return NULL;
}

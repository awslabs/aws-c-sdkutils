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

static void s_on_expr_array_element_clean_up(void *element) {
    struct aws_endpoints_expr *expr = element;
    aws_endpoints_expr_clean_up(expr);
}

static void s_on_condition_array_element_clean_up(void *element) {
    struct aws_endpoints_condition *condition = element;
    aws_endpoints_condition_clean_up(condition);
}

/*
 * Helper: read a big-endian i32 from cursor.
 */
static int s_read_i32(struct aws_byte_cursor *cursor, int32_t *out) {
    uint32_t val;
    if (!aws_byte_cursor_read_be32(cursor, &val)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    *out = (int32_t)val;
    return AWS_OP_SUCCESS;
}

/*
 * Helper: resolve function name cursor to enum via hash lookup.
 */
static enum aws_endpoints_fn_type s_resolve_fn(struct aws_byte_cursor fn_name) {
    uint64_t hash = aws_hash_byte_cursor_ptr(&fn_name);
    for (int idx = AWS_ENDPOINTS_FN_FIRST; idx < AWS_ENDPOINTS_FN_LAST; ++idx) {
        if (aws_endpoints_fn_name_hash[idx] == hash) {
            return (enum aws_endpoints_fn_type)idx;
        }
    }
    /* Unknown function (e.g. ite, coalesce, split) - caller handles */
    return AWS_ENDPOINTS_FN_LAST;
}

static int s_validate_magic_number(struct aws_byte_cursor *cursor) {
    uint32_t magic;
    if (!aws_byte_cursor_read_be32(cursor, &magic)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    if (magic != BDD_MAGIC_NUMBER) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    return AWS_OP_SUCCESS;
}

static int s_load_string_table(struct aws_byte_cursor *cursor, struct aws_byte_cursor *out_blob) {
    uint32_t blob_size;
    if (!aws_byte_cursor_read_be32(cursor, &blob_size)) {
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
    if (!aws_byte_cursor_read_be16(cursor, &offset) || !aws_byte_cursor_read_be16(cursor, &length)) {
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
    if (!aws_byte_cursor_read_be16(cursor, &count)) {
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
    struct aws_allocator *allocator,
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
            out_expr->type = AWS_ENDPOINTS_EXPR_STRING;
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
            if (s_read_i32(cursor, &int_val)) {
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
            out_expr->e.reference = ref_cur;
            break;
        }

        case 5: { /* Function */
            struct aws_byte_cursor fn_name;
            if (s_read_string_ref(cursor, blob, &fn_name)) {
                return AWS_OP_ERR;
            }

            uint16_t argc;
            if (!aws_byte_cursor_read_be16(cursor, &argc)) {
                return AWS_OP_ERR;
            }

            out_expr->type = AWS_ENDPOINTS_EXPR_FUNCTION;
            out_expr->e.function.fn = s_resolve_fn(fn_name);

            if (aws_array_list_init_dynamic(
                    &out_expr->e.function.argv, allocator, argc, sizeof(struct aws_endpoints_expr))) {
                return AWS_OP_ERR;
            }

            for (uint16_t i = 0; i < argc; ++i) {
                struct aws_endpoints_expr arg;
                if (s_decode_value(allocator, cursor, blob, &arg)) {
                    aws_array_list_deep_clean_up(&out_expr->e.function.argv, s_on_expr_array_element_clean_up);
                    return AWS_OP_ERR;
                }
                if (aws_array_list_push_back(&out_expr->e.function.argv, &arg)) {
                    aws_endpoints_expr_clean_up(&arg);
                    aws_array_list_deep_clean_up(&out_expr->e.function.argv, s_on_expr_array_element_clean_up);
                    return AWS_OP_ERR;
                }
            }
            break;
        }

        case 6: { /* Array */
            uint16_t length;
            if (!aws_byte_cursor_read_be16(cursor, &length)) {
                return AWS_OP_ERR;
            }

            out_expr->type = AWS_ENDPOINTS_EXPR_ARRAY;
            if (aws_array_list_init_dynamic(&out_expr->e.array, allocator, length, sizeof(struct aws_endpoints_expr))) {
                return AWS_OP_ERR;
            }

            for (uint16_t i = 0; i < length; ++i) {
                struct aws_endpoints_expr elem;
                if (s_decode_value(allocator, cursor, blob, &elem)) {
                    aws_array_list_deep_clean_up(&out_expr->e.array, s_on_expr_array_element_clean_up);
                    return AWS_OP_ERR;
                }
                if (aws_array_list_push_back(&out_expr->e.array, &elem)) {
                    aws_endpoints_expr_clean_up(&elem);
                    aws_array_list_deep_clean_up(&out_expr->e.array, s_on_expr_array_element_clean_up);
                    return AWS_OP_ERR;
                }
            }
            break;
        }

        case 7: { /* Object */
            uint16_t length;
            if (!aws_byte_cursor_read_be16(cursor, &length)) {
                return AWS_OP_ERR;
            }

            out_expr->type = AWS_ENDPOINTS_EXPR_OBJECT;
            if (aws_array_list_init_dynamic(
                    &out_expr->e.object, allocator, length, sizeof(struct aws_endpoints_kv_pair))) {
                return AWS_OP_ERR;
            }

            for (uint16_t i = 0; i < length; ++i) {
                struct aws_byte_cursor key_cur;
                if (s_read_string_ref(cursor, blob, &key_cur)) {
                    goto object_error;
                }

                struct aws_endpoints_kv_pair pair;
                pair.allocator = allocator;
                pair.key = key_cur;
                pair.value = aws_mem_calloc(allocator, 1, sizeof(struct aws_endpoints_expr));
                if (!pair.value) {
                    goto object_error;
                }

                if (s_decode_value(allocator, cursor, blob, pair.value)) {
                    aws_mem_release(allocator, pair.value);
                    goto object_error;
                }

                if (aws_array_list_push_back(&out_expr->e.object, &pair)) {
                    aws_endpoints_expr_clean_up(pair.value);
                    aws_mem_release(allocator, pair.value);
                    goto object_error;
                }
                continue;

            object_error:
                /* Clean up already-pushed pairs */
                for (size_t j = 0; j < aws_array_list_length(&out_expr->e.object); ++j) {
                    struct aws_endpoints_kv_pair *p = NULL;
                    aws_array_list_get_at_ptr(&out_expr->e.object, (void **)&p, j);
                    if (p && p->value) {
                        aws_endpoints_expr_clean_up(p->value);
                        aws_mem_release(p->allocator, p->value);
                    }
                }
                aws_array_list_clean_up(&out_expr->e.object);
                return AWS_OP_ERR;
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
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_endpoints_condition *cond) {

    uint8_t opcode;
    if (!aws_byte_cursor_read_u8(cursor, &opcode) || opcode != BDD_OP_CONDITION) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor fn_name;
    if (s_read_string_ref(cursor, blob, &fn_name)) {
        return AWS_OP_ERR;
    }

    uint16_t argc;
    if (!aws_byte_cursor_read_be16(cursor, &argc)) {
        return AWS_OP_ERR;
    }

    cond->expr.type = AWS_ENDPOINTS_EXPR_FUNCTION;
    cond->expr.e.function.fn = s_resolve_fn(fn_name);

    if (aws_array_list_init_dynamic(&cond->expr.e.function.argv, allocator, argc, sizeof(struct aws_endpoints_expr))) {
        return AWS_OP_ERR;
    }

    for (uint16_t i = 0; i < argc; ++i) {
        struct aws_endpoints_expr arg;
        if (s_decode_value(allocator, cursor, blob, &arg)) {
            goto on_error;
        }
        if (aws_array_list_push_back(&cond->expr.e.function.argv, &arg)) {
            aws_endpoints_expr_clean_up(&arg);
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
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_endpoints_expr_clean_up(&cond->expr);
    return AWS_OP_ERR;
}

static int s_load_conditions(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_array_list *out_conditions) {

    uint16_t count;
    if (!aws_byte_cursor_read_be16(cursor, &count)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (aws_array_list_init_dynamic(out_conditions, allocator, count, sizeof(struct aws_endpoints_condition))) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    for (uint16_t i = 0; i < count; ++i) {
        struct aws_endpoints_condition cond;
        AWS_ZERO_STRUCT(cond);

        if (s_parse_one_condition(allocator, cursor, blob, &cond)) {
            goto error;
        }
        if (aws_array_list_push_back(out_conditions, &cond)) {
            aws_endpoints_condition_clean_up(&cond);
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    aws_array_list_deep_clean_up(out_conditions, s_on_condition_array_element_clean_up);
    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}

static int s_load_results(
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cursor,
    struct aws_byte_cursor blob,
    struct aws_array_list *out_results) {

    uint16_t count;
    if (!aws_byte_cursor_read_be16(cursor, &count)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (aws_array_list_init_dynamic(out_results, allocator, count + 1, sizeof(struct aws_endpoints_bdd_result))) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Insert NoMatchRule as results[0] */
    struct aws_endpoints_bdd_result no_match;
    AWS_ZERO_STRUCT(no_match);
    no_match.type = AWS_ENDPOINTS_RESOLVED_ERROR;
    no_match.data.error.error = aws_byte_cursor_from_c_str("No matching rule");
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

            if (s_read_string_ref(cursor, blob, &result.data.endpoint.url)) {
                goto error;
            }
            if (s_read_string_ref(cursor, blob, &result.data.endpoint.properties_json)) {
                goto error;
            }

        } else if (opcode == BDD_OP_RESULT_ERROR) {
            result.type = AWS_ENDPOINTS_RESOLVED_ERROR;

            if (s_read_string_ref(cursor, blob, &result.data.error.error)) {
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

    if (s_read_i32(cursor, out_root_ref)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    uint32_t node_count;
    if (!aws_byte_cursor_read_be32(cursor, &node_count)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    uint16_t base64_length;
    if (!aws_byte_cursor_read_be16(cursor, &base64_length)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (cursor->len < base64_length) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_byte_cursor base64_data = aws_byte_cursor_advance(cursor, base64_length);

    size_t decoded_size = 0;
    if (aws_base64_compute_decoded_len(&base64_data, &decoded_size)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_buf decoded_buf;
    if (aws_byte_buf_init(&decoded_buf, allocator, decoded_size)) {
        return AWS_OP_ERR;
    }

    if (aws_base64_decode(&base64_data, &decoded_buf)) {
        aws_byte_buf_clean_up(&decoded_buf);
        return AWS_OP_ERR;
    }

    size_t expected_size = node_count * 12; /* 3 int32s per node */
    if (decoded_buf.len != expected_size) {
        aws_byte_buf_clean_up(&decoded_buf);
        return AWS_OP_ERR;
    }

    if (aws_array_list_init_dynamic(out_nodes, allocator, node_count, sizeof(struct aws_endpoints_bdd_node))) {
        aws_byte_buf_clean_up(&decoded_buf);
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor node_cursor = aws_byte_cursor_from_buf(&decoded_buf);
    for (uint32_t i = 0; i < node_count; ++i) {
        struct aws_endpoints_bdd_node node;
        if (s_read_i32(&node_cursor, &node.condition_index) || s_read_i32(&node_cursor, &node.high_ref) ||
            s_read_i32(&node_cursor, &node.low_ref)) {
            aws_array_list_clean_up(out_nodes);
            aws_byte_buf_clean_up(&decoded_buf);
            return AWS_OP_ERR;
        }
        aws_array_list_push_back(out_nodes, &node);
    }

    aws_byte_buf_clean_up(&decoded_buf);
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

    if (s_load_conditions(allocator, &bytecode, engine->string_blob, &engine->conditions)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_ENDPOINTS_RESOLVE, "Failed to load conditions");
        goto error;
    }

    if (s_load_results(allocator, &bytecode, engine->string_blob, &engine->results)) {
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
    aws_array_list_deep_clean_up(&engine->conditions, s_on_condition_array_element_clean_up);
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

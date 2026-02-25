#include <aws/sdkutils/endpoints_bdd_engine.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/sdkutils/partitions.h>
#include <aws/common/byte_buf.h>
#include <aws/common/file.h>
#include <aws/common/error.h>
#include <stdio.h>

static int s_read_file(
    struct aws_byte_buf *out_buf,
    struct aws_allocator *alloc,
    const struct aws_byte_cursor filename_cur) {
    AWS_ZERO_STRUCT(*out_buf);
    struct aws_string *mode = aws_string_new_from_c_str(alloc, "r");
    struct aws_string *filename = aws_string_new_from_cursor(alloc, &filename_cur);
    FILE *fp = aws_fopen_safe(filename, mode);
    aws_string_destroy(filename);
    aws_string_destroy(mode);
    if (!fp) {
        printf("Failed to open file\n");
        return AWS_OP_ERR;
    }

    int64_t file_size = 0;
    if (aws_file_get_length(fp, &file_size) != AWS_OP_SUCCESS) {
        printf("Failed to get file length\n");
        fclose(fp);
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_init(out_buf, alloc, (size_t)file_size) != AWS_OP_SUCCESS) {
        printf("Failed to init byte buf\n");
        fclose(fp);
        return AWS_OP_ERR;
    }
    size_t read = fread(out_buf->buffer, 1, (size_t)file_size, fp);
    fclose(fp);

    out_buf->len = read;
    return AWS_OP_SUCCESS;
}

int main(void) {
    struct aws_allocator *allocator = aws_default_allocator();
    aws_sdkutils_library_init(allocator);

    struct aws_byte_buf bytecode;
    if (aws_byte_buf_init_from_file(&bytecode, allocator, "bdd_test.bin") != AWS_OP_SUCCESS) {
        printf("Failed to load bytecode: %s\n", aws_error_name(aws_last_error()));
        return 1;
    }
    printf("Loaded bytecode: %zu bytes\n", bytecode.len);

    struct aws_byte_buf partitions_buf;
    if (s_read_file(&partitions_buf, allocator, aws_byte_cursor_from_c_str("sample_partitions.json")) != AWS_OP_SUCCESS) {
        printf("Failed to load partitions file: %s\n", aws_error_name(aws_last_error()));
        aws_byte_buf_clean_up(&bytecode);
        return 1;
    }
    printf("Loaded partitions: %zu bytes\n", partitions_buf.len);
    
    struct aws_byte_cursor partitions_json = aws_byte_cursor_from_buf(&partitions_buf);
    struct aws_partitions_config *partitions = aws_partitions_config_new_from_string(
        allocator, partitions_json);
    if (!partitions) {
        printf("Failed to parse partitions: %s\n", aws_error_name(aws_last_error()));
        aws_byte_buf_clean_up(&partitions_buf);
        aws_byte_buf_clean_up(&bytecode);
        return 1;
    }
    printf("Parsed partitions successfully\n");

    struct aws_endpoints_bdd_engine *engine = aws_endpoints_bdd_engine_new_from_bytecode(
        allocator, aws_byte_cursor_from_buf(&bytecode), partitions);
    if (!engine) {
        printf("Failed to create engine: %s\n", aws_error_name(aws_last_error()));
        aws_partitions_config_release(partitions);
        aws_byte_buf_clean_up(&partitions_buf);
        aws_byte_buf_clean_up(&bytecode);
        return 1;
    }
    printf("Created engine successfully\n");

    printf("Version: %.*s\n", (int)engine->version.len, engine->version.ptr);
    printf("Parameters: %zu\n", aws_hash_table_get_entry_count(&engine->parameters));
    printf("Conditions: %zu\n", aws_array_list_length(&engine->conditions));
    printf("Results: %zu\n", aws_array_list_length(&engine->results));

    aws_endpoints_bdd_engine_release(engine);
    aws_partitions_config_release(partitions);
    aws_byte_buf_clean_up(&partitions_buf);
    aws_byte_buf_clean_up(&bytecode);

    return 0;
}

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/sdkutils/sdkutils.h>

/* clang-format off */
static struct aws_error_info s_errors[] = {
    AWS_DEFINE_ERROR_INFO(AWS_ERROR_SDKUTILS_GENERAL, "General error in SDK Utility library", "aws-c-sdkutils"),
    AWS_DEFINE_ERROR_INFO(AWS_ERROR_SDKUTILS_PARSE_FATAL, "Parser encountered a fatal error", "aws-c-sdkutils"),
    AWS_DEFINE_ERROR_INFO(AWS_ERROR_SDKUTILS_PARSE_RECOVERABLE, "Parser encountered an error, but recovered", "aws-c-sdkutils"),
};
/* clang-format on */

static struct aws_error_info_list s_sdkutils_error_info = {
    .error_list = s_errors,
    .count = sizeof(s_errors) / sizeof(struct aws_error_info),
};

static struct aws_log_subject_info s_log_subject_infos[] = {
    DEFINE_LOG_SUBJECT_INFO(
        AWS_LS_SDKUTILS_GENERAL,
        "SDKUtils",
        "Subject for SDK utility logging that defies categorization."),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_SDKUTILS_PROFILE, "AWSProfile", "Subject for AWS Profile parser and utilities"),
};

static struct aws_log_subject_info_list s_sdkutils_log_subjects = {
    .subject_list = s_log_subject_infos,
    .count = AWS_ARRAY_SIZE(s_log_subject_infos),
};

static int s_library_init_count = 0;

void aws_sdkutils_library_init(struct aws_allocator *allocator) {
    if (s_library_init_count++ != 0) {
        return;
    }

    aws_common_library_init(allocator);

    aws_register_error_info(&s_sdkutils_error_info);
    aws_register_log_subject_info_list(&s_sdkutils_log_subjects);
}

void aws_sdkutils_library_clean_up(void) {
    if (--s_library_init_count != 0) {
        return;
    }

    aws_unregister_log_subject_info_list(&s_sdkutils_log_subjects);
    aws_unregister_error_info(&s_sdkutils_error_info);

    aws_common_library_clean_up();
}

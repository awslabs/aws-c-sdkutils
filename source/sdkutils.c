
#include <aws/sdkutils/sdkutils.h>

void aws_sdkutils_library_init(struct aws_allocator *allocator) {
  aws_common_library_init(allocator);
}

void aws_sdkutils_library_clean_up(void) { aws_common_library_clean_up(); }

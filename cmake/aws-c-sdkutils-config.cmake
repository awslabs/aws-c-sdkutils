include(CMakeFindDependencyMacro)
include(AwsCrtLoadTarget)

find_dependency(aws-c-common)

aws_load_target_default(@PROJECT_NAME@)

AC_PREREQ([2.71])
AC_INIT([aclcopy],[1.0.1],[pen@lysator.liu.se],[aclcopy],[https://github.com/ptrrkssn/aclcopy])
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_SRCDIR([aclcopy.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_LN_S
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for header files.
AC_CHECK_HEADERS([sys/acl.h acl/libacl.h])
AC_CHECK_HEADERS([sys/xattr.h sys/extattr.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE

AC_CHECK_FUNCS([extattr_get_fd fgetxattr extattr_set_fd fsetxattr extattr_delete_fd fremovexattr attropen])

AC_SEARCH_LIBS([acl_get_fd], [acl], [], [])
AC_CHECK_FUNCS([acl_get_fd_np acl_get_entry_type_np acl_get_flagset_np acl_get_perm_np acl_strip_np])
AC_CHECK_FUNCS([acl_get_file acl_get_perm acl_get_flag_np])

AC_CONFIG_FILES([Makefile pkgs/Makefile pkgs/Makefile.port pkgs/aclcopy.rb pkgs/pkginfo pkgs/aclcopy.spec pkgs/pkg-descr pkgs/build.sh pkgs/control])
AC_OUTPUT

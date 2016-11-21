AC_PREREQ([2.69])
AC_INIT([tcpinfo.c], [1.0], [marco.guerri.dev@fastmail.com])
AC_CONFIG_SRCDIR([tcpinfo.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([socket])

# Checks for fields in tcpinfo struct 
AC_CHECK_MEMBERS([struct tcp_info.tcpi_state,
                  struct tcp_info.tcpi_ca_state,
                  struct tcp_info.tcpi_retransmits,
                  struct tcp_info.tcpi_probes,
                  struct tcp_info.tcpi_backoff,
                  struct tcp_info.tcpi_options,
                  struct tcp_info.tcpi_rto,
                  struct tcp_info.tcpi_lost,
                  struct tcp_info.tcpi_retrans,
                  struct tcp_info.tcpi_total_retrans,
                  struct tcp_info.tcpi_advmss,
                  struct tcp_info.tcpi_ato,
                  struct tcp_info.tcpi_fackets], 
                [],[],
                [[#include <linux/tcp.h>]])

AC_OUTPUT

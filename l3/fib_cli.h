#ifndef FIB_CLI_H
#define FIB_CLI_H

#include "fib.h"

#define FIB_SOCK_NAME   "fibd.sock"
#define FIB_SOCK_DEFAULT "/tmp/fibd.sock"

int cli_write_schema(void);
int cli_load_runtime_config(fib_table_t *fib);
int cli_save_runtime_key(const char *key, const char *value);

#endif /* FIB_CLI_H */

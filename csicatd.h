# include <glib.h>
# include <stdio.h>
# include <string.h>
# include <time.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <signal.h>
# include <fcntl.h>
# include <unistd.h>
# include <syslog.h>
# include <stdlib.h>
# include <getopt.h>
# include <stdarg.h>

void redirecciona(GPid pid,gint status,gchar** arg);

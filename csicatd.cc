# include "csicatd.h"

int main(int argc, char** argv)
{
	gchar** arg;
	gchar* name;
	GError* gerror = NULL;
	
	name = g_new0(char,100);
	strcpy(name,"/usr/sbin/sicatd");
	
	arg = g_new0(char*,2);
	arg[0] = name;

    while (1){
		g_spawn_sync(NULL,arg,NULL,(GSpawnFlags) (G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL) ,NULL,NULL,NULL,NULL,NULL,&gerror);
		sleep(5);
    }				
	return 0;
}

#include <stdlib.h>
#include <stdio.h>

#define COUNT 3

int main(int argc, char **argv)
{
	system("echo bash: > pids");
	system("ps -a | grep bash | awk '{print $1}' >> pids");
	system("echo \" \nRequested : \" >> pids ");
	char command[100];
	int i;
	for(i = 1; i < argc; ++i) {
		snprintf(command, 99, "%s %s %s", "ps -a | grep", argv[i], "| awk '{print $1}' >> pids");
		system(command);
	}

	return 0;
}

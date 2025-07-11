// cc -o Daemon Daemon.c

//Libraries

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <seccomp.h>


volatile sig_atomic_t back_daemon = 1;

void handle_signal(int sig) {
	syslog(LOG_INFO, "Signal %d received, shutting down", sig);
	back_daemon = 0;
}

//Drop root privleges
void drop_privileges(const char *username) {
	struct passwd *pw = getpwnam(username);
	if (!pw) {
		syslog(LOG_ERR, "User %s not able to be found: %s", username, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setgid(pw->pw_gid) != 0) {
		syslog(LOG_ERR, "setgid() failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (setuid(pw->pw_uid) != 0) {
		syslog(LOG_ERR, "Privileges failed to drop to %s: %s", username, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

//PID - create and lock
void create_pid_file(const char *pidfile) {
	int fd = open(pidfile, O_RDWR | O_CREAT, 0640);
	if (fd < 0) {
		syslog(LOG_ERR, "PID failed to open %s: %s", pidfile, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (lockf(fd, F_TLOCK, 0) < 0) {
		syslog(LOG_ERR, "Invalid. Daemon already running.");
		exit(EXIT_FAILURE);
	}

	char pid_str[16];
	snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
	write(fd, pid_str, strlen(pid_str));
}


void apply_seccomp() {
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	if (seccomp_load(ctx) != 0) {
		syslog(LOG_ERR, "Failed to load");
		exit(EXIT_FAILURE);
	}
}



//Turn into daemon
void daemonize() {
	pid_t pid;

	// Fork
	pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	if (setsid() < 0) {
		exit(EXIT_FAILURE);
	}



	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);

	pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	//secure file creation
	umask(027);

	//changes working directory
	if (chdir("/") < 0) {
		exit(EXIT_FAILURE);
	}


	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	int null_fd = open("/dev/null", O_RDWR);
	dup(null_fd);
	dup(null_fd);
}

void cleanup() {
	syslog(LOG_INFO, "Clean Exit");
	closelog();
}

int main() {

	//Turn into daemon
	openlog("TimeDaemon", LOG_PID | LOG_CONS, LOG_DAEMON);
	atexit(cleanup);

	daemonize();

	create_pid_file("/run/Daemon.pid");

	if (prctl(PR_SET_DUMPABLE, 0) != 0) {
		syslog(LOG_WARNING, "Disable core dumps malfunction: %s", strerror(errno));
	}


	drop_privileges("nobody");  //This drops it from root privleges to low-privelege user

	syslog(LOG_INFO, "Daemon started");


	while (back_daemon) {
		time_t now = time(NULL);
		if (now == (time_t)-1) {
			syslog(LOG_ERR, "Failed to get time: %s", strerror(errno));
		} else {
			struct tm*tm_info = localtime(&now);
			if (tm_info) {
				char time_str[26];
				strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
				syslog(LOG_INFO, "Current time: %s", time_str);
			} else {
				syslog(LOG_ERR, "Local time failed: %s", strerror(errno));
			}
		}
		sleep(1);
	}

	syslog(LOG_INFO, "Time Daemon shutting down.");
	closelog();

	return EXIT_SUCCESS;
}

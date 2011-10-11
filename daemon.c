/*
 ** Copyright (C) 2010 Hagen Paul Pfeifer <hagen@jauu.net>

 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation; either version 2 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software 
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include  "ldnsd.h"


#include <fcntl.h>
#include <sys/stat.h>

#include <unistd.h>

#include <syslog.h>

/* signale stuff */
#define __GNU_SOURCE
#include <string.h>
#include <signal.h>

void fatal_sighand(int);
void term_sighand(int);
static int close_open_fds(int);

extern int errno;
extern int is_daemon;

int
init_pidfile(void)
{

	int lffd, lock_pid, kill_ret, lock_ret;
	FILE *lockfp;
	char *lockname, *lfs, pid_buff[17];
	struct flock flock_strct;

	if (optsp->pidfile) {
		lockname = optsp->pidfile;
	} else {
		lockname = PIDFILE;
	}

	lffd = open(lockname, O_RDWR | O_CREAT | O_EXCL, 0644);

	if (lffd == -1) { /* o.k., file exist (maybe) */
		lockfp = fopen(lockname, "r");

		if (lockfp == 0)
			error_quit("Failure in lockfile! It exits but is not readable: %s\n", lockfp);

		lfs = fgets(pid_buff, 16, lockfp);

		if (lfs != 0) {
			if (pid_buff[strlen(pid_buff) - 1] == '\n')
				pid_buff[strlen(pid_buff) - 1] = 0;

			lock_pid = strtoul(pid_buff, (char **)0, 10);

			kill_ret = kill(lock_pid, 0);
			if (kill_ret == 0) {
				error_quit("Lockfile detected (%s) Owned by process %d\n",
						lockname, lock_pid);
			} else {
				if (errno == ESRCH) { /* does not exist */
					error_quit("Lockfile (%s) detected but no process with this id (%d)\n"
							"Delete lockfile and rerun programm!\n",
							lockname, lock_pid);
				} else {
					error_quit("Could not accquire lockfile");
				}
			}
		} else {
			error_quit("Could not read lockfile (%s)!\n", lockname);
		}

		fclose(lockfp);

		flock_strct.l_type   = F_WRLCK;   /* write lock */
		flock_strct.l_whence = SEEK_SET; 
		flock_strct.l_len    = 0;
		flock_strct.l_start  = 0;
		flock_strct.l_pid    = 0;

		if ( (lock_ret = fcntl(lffd, F_SETLK, &flock_strct)) < 0) {
			close(lffd);
			error_quit("Can't get a file lock!\n");
		}
	}

	return lffd;
}

int init_sighandler(void)
{
	struct sigaction sigterm_sa;

	/* ignore some unimportend signals */
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGURG,  SIG_IGN);
	signal(SIGXCPU, SIG_IGN);
	signal(SIGXFSZ, SIG_IGN);
	signal(SIGVTALRM, SIG_IGN);
	signal(SIGPROF, SIG_IGN);
	signal(SIGIO, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	/* normally you use SIGHUP to reread the conf file */
	signal(SIGHUP, SIG_IGN);


	/* fatal failures -> logging and exit */
	signal(SIGQUIT, fatal_sighand);
	signal(SIGILL, fatal_sighand);
	signal(SIGTRAP, fatal_sighand);
	signal(SIGABRT, fatal_sighand);
	signal(SIGIOT, fatal_sighand);
	signal(SIGBUS, fatal_sighand);
	signal(SIGFPE, fatal_sighand);
	signal(SIGSEGV, fatal_sighand);
	signal(SIGSTKFLT, fatal_sighand);
	signal(SIGCONT, fatal_sighand);
	signal(SIGPWR, fatal_sighand);
	signal(SIGSYS, fatal_sighand);

	/* SIGTERM -> shut down immediately */
	sigterm_sa.sa_handler = term_sighand;
	sigemptyset(&sigterm_sa.sa_mask);
	sigterm_sa.sa_flags = 0;
	sigaction(SIGTERM, &sigterm_sa, NULL);

	return 0;
}

void fatal_sighand(int signal)
{
#ifdef HAVE_STRSIGNAL
	error_quit("FATAL SIGNAL: %s\n", strsignal(signal));
#else
	error_quit("FATAL SIGNAL: %d\n", signal);
#endif

}

void term_sighand(int signal)
{

	cleanup();
	debug_msg("Exiting elohim, bye!");
	exit(0);

}

int daemonize(const char *pname, int lockfd)
{
	pid_t pid;
	char pid_buff[7];

	if ((pid = fork()) < 0) {
		return -1;
	}
	else if (pid != 0) { /* parent goes $HOME */
		exit(0);
	}

	/* we are the child! */
	setsid();

	if ((pid = fork()) < 0) {
		return -1;
	}
	else if (pid != 0) { /* parent goes $HOME */
		exit(0);
	}

	chdir("/");
	umask(0);

	is_daemon = 1;

	if ((ftruncate(lockfd, 0)) < 0)
		error_quit("Can't truncate pidfile!\n");

	/* store our pid in pidfile */
	/* FIXME: through a leeak of snprintf there */
	/* are some tiny security hole here.        */
	/* Possible solution: test function through */
	/* configure script                         */
	snprintf(pid_buff, sizeof(pid_buff), "%d\n", (int)getpid());
	write(lockfd, pid_buff, strlen(pid_buff));

	/* and set lock_fd global, so error routines can delete */
	/* lockfile */
	optsp->lock_fd = lockfd;

	openlog(pname, LOG_PID, LOG_USER | LOG_INFO);

	close_open_fds(lockfd);

	/* own process group */
	setpgrp();

	debug_msg("elohim started ...");

	return 0;
}

static int close_open_fds(int lockfd)
{
	int max_fd, i, std_fd;

	if ((max_fd = (int) sysconf(_SC_OPEN_MAX)) < 0)
		max_fd = 256;

	for (i = max_fd - 1; i >= 0; --i) {
		if (i != lockfd) /* take care of lockfile */
			close(i);
	}

	/* ... and open fd{0, 1, 2} */
	std_fd = open("/dev/null", O_RDWR);
	dup(std_fd);
	dup(std_fd);

	return 0;
}

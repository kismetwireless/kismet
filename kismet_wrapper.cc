/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include "config.h"

/* Blob of globals since sighandler needs them */
vector<string> postcli_err;
pid_t srvpid = -1, clipid = -1;
int rpipe[2], epipe[2], max_fd;
fd_set rset;
FILE *out, *err;
struct timeval tim;
int check_err = 0, check_out = 0;
char ret[2048];
int reap_pending = 0;

/* Sighandler/Reaper */
void reap(int sig) {
	check_err = 1;
	check_out = 1;

	reap_pending++;

	if (clipid > 0) {
		kill(clipid, SIGTERM);
		if (reap_pending <= 1)
			wait4(clipid, NULL, 0, NULL);
	}

	if (srvpid > 0) {
		kill(srvpid, SIGTERM);
	}

	while (1) {
		FD_ZERO(&rset);

		if (check_out == 0 && check_err == 0)
			break;

		if (check_out)
			FD_SET(rpipe[0], &rset);
		if (check_err)
			FD_SET(epipe[0], &rset);

		tim.tv_sec = 0;
		tim.tv_usec = 500000;

		if (select(max_fd + 1, &rset, NULL, NULL, &tim) < 0) {
			fprintf(stderr, "Select failed: %s\n", strerror(errno));
			break;
		}

		if (FD_ISSET(epipe[0], &rset)) {
			if (fgets(ret, 2048, err) == NULL || feof(err)) {
				if (out == NULL || (out != NULL && feof(out)))
					break;

				fclose(err);
				err = NULL;
				close(epipe[0]);
				check_err = 0;
				continue;
			}

			if (clipid == -1) {
				fprintf(stderr, "%s", ret);
			} else {
				postcli_err.push_back(ret);
			}
		}

		if (FD_ISSET(rpipe[0], &rset)) {
			if (fgets(ret, 2048, out) == NULL || feof(out)) {
				if (err == NULL || (err != NULL && feof(err)))
					break;

				fclose(out);
				out = NULL;
				close(rpipe[0]);
				check_out = 0;
				continue;
			}

			fprintf(stdout, "%s", ret);
		}
	}

	for (unsigned int x = 0; x < postcli_err.size(); x++) {
		fprintf(stderr, "%s", postcli_err[x].c_str());
	}

	if (reap_pending <= 1)
		wait4(srvpid, NULL, 0, NULL);

	printf("Done.\n");
}

int main(int argc, char *argv[], char *envp[]) {
	vector<string> server_opt, cli_opt;
	char **eargv;
	int optmode = 0;

	for (int x = 1; x < argc; x++) {
		if (strcmp(argv[x], "-h") == 0 ||
			strcmp(argv[x], "--help") == 0) {
			printf("Kismet wrapper script\n\n"
				   "Usage:\n"
				   "  kismet (server options) -- (client options)\n"
				   "\n"
				   "For server and client specific options, use:\n"
				   "  kismet_server --help\n"
				   "  kismet_client --help\n");
			exit(0);
		}

		if (strcmp(argv[x], "--") == 0) {
			optmode = 1;
			continue;
		}

		if (optmode == 0) {
			server_opt.push_back(string(argv[x]));
		} else {
			cli_opt.push_back(string(argv[x]));
		}
	}

	if (pipe(rpipe) != 0 || pipe(epipe) != 0) {
		fprintf(stderr, "Error creating pipe: %s\n", strerror(errno));
		exit(5);
	}

	fcntl(rpipe[1], F_SETFD, fcntl(rpipe[1], F_GETFD) & ~1);
	fcntl(epipe[1], F_SETFD, fcntl(epipe[1], F_GETFD) & ~1);

	if ((srvpid = fork()) < 0) {
		fprintf(stderr, "Error forking: %s\n", strerror(errno));
		exit(5);
	} else if (srvpid == 0) {
		/* eargv bumped by 2 to make room for the --silent and argv[0] */
		eargv = (char **) malloc(sizeof(char *) * (server_opt.size() + 3));
		for (unsigned int x = 0; x < server_opt.size(); x++) {
			eargv[x + 2] = strdup(server_opt[x].c_str());
		}

		snprintf(ret, 2048, "%s/%s", BIN_LOC, "kismet_server");
		eargv[0] = strdup(ret);
		eargv[1] = strdup("--silent");
		eargv[server_opt.size() + 2] = NULL;

		printf("Launching kismet_server: %s\n", eargv[0]);
		fflush(stdout);

		/* Dup over stdout/stderr so we can hijack the output */
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		dup2(rpipe[1], STDOUT_FILENO);
		dup2(epipe[1], STDERR_FILENO);

		/* We don't need these anymore */
		close(rpipe[0]);
		close(rpipe[1]);
		close(epipe[0]);
		close(epipe[1]);

		execv(eargv[0], eargv);

		fprintf(stderr, "Failed to launch %s: %s\n",
				eargv[0], strerror(errno));

		exit(255);
	} 

	signal(SIGINT, &reap);
	signal(SIGTERM, &reap);
	signal(SIGQUIT, &reap);
	signal(SIGHUP, &reap);

	close(rpipe[1]);
	close(epipe[1]);

	out = fdopen(rpipe[0], "r");
	err = fdopen(epipe[0], "r");

	max_fd = 0;
	if (rpipe[0] > max_fd)
		max_fd = rpipe[0];
	if (epipe[0] > max_fd)
		max_fd = epipe[0];

	while (1) {
		FD_ZERO(&rset);

		FD_SET(rpipe[0], &rset);
		FD_SET(epipe[0], &rset);

		tim.tv_sec = 0;
		tim.tv_usec = 500000;

		if (clipid > -1 &&
			wait4(clipid, NULL, WNOHANG, NULL) < 0) {
			break;
		}

		if (clipid == -1 &&
			wait4(srvpid, NULL, WNOHANG, NULL) < 0) {
			break;
		}

		int sel;
		if ((sel = select(max_fd + 1, &rset, NULL, NULL, &tim)) < 0) {
			fprintf(stderr, "Select failed: %s\n", strerror(errno));
			break;
		}

		if (FD_ISSET(epipe[0], &rset)) {
			if (fgets(ret, 2048, err) == NULL ||
				feof(err)) {
				break;
			}

			/* Capture stderr if the client is running */
			if (clipid == -1) {
				fprintf(stderr, "%s", ret);
			} else {
				postcli_err.push_back(ret);
			}

			continue;
		}

		if (clipid >= 0 && check_err == 0)
			check_err = 1;

		if (FD_ISSET(rpipe[0], &rset)) {
			if (fgets(ret, 2048, out) == NULL ||
				feof(out)) {
				break;
			}

			/* Squelch stdout if we're running the client */
			if (clipid == -1) {
				fprintf(stdout, "%s", ret);
			}

			/* Kismet actually launched */
			if (strstr(ret, "Gathering packets...") != NULL && clipid == -1) {
				sleep(1);
				if ((clipid = fork()) < 0) {
					fprintf(stderr, "Failed to fork for client: %s\n",
							strerror(errno));
					break;
				} else if (clipid == 0) {
					close(rpipe[0]);
					close(epipe[0]);

					eargv = (char **) malloc(sizeof(char *) * 
											 (server_opt.size() + 2));

					for (unsigned int x = 0; x < cli_opt.size(); x++) {
						eargv[x + 2] = strdup(cli_opt[x].c_str());
					}

					snprintf(ret, 2048, "%s/%s", BIN_LOC, "kismet_client");
					eargv[0] = strdup(ret);
					eargv[server_opt.size() + 1] = NULL;

					printf("Launching kismet_client: %s\n", eargv[0]);

					execv(eargv[0], eargv);

					fprintf(stderr, "Failed to launch kismet_client\n");
					exit(255);
				}

				fprintf(stderr, "Launched client, pid %d\n", clipid);
			}
		}
	}

	wait4(clipid, NULL, 0, NULL);

	reap(0);
}


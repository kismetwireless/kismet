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

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <errno.h>
#include <sys/wait.h>

#include "config.h"

int main(int argc, char *argv[], char *envp[]) {
	vector<string> server_opt, cli_opt, postcli_err;
	char **eargv;
	int optmode = 0;
	char ret[2048];
	pid_t srvpid = -1, clipid = -1;
	int rpipe[2], epipe[2], max_fd;
	fd_set rset;
	FILE *out, *err;
	struct timeval tm;

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

	/* eargv bumped by 2 to make room for the --silent and argv[0] */
	eargv = (char **) malloc(sizeof(char *) * (server_opt.size() + 3));
	for (unsigned int x = 0; x < server_opt.size(); x++) {
		eargv[x + 2] = strdup(server_opt[x].c_str());
	}

	snprintf(ret, 2048, "%s/%s", BIN_LOC, "kismet_server");
	eargv[0] = strdup(ret);
	eargv[1] = strdup("--silent");
	eargv[server_opt.size() + 2] = NULL;

	if (pipe(rpipe) != 0 || pipe(epipe) != 0) {
		fprintf(stderr, "Error creating pipe: %s\n", strerror(errno));
		exit(5);
	}

	if ((srvpid = fork()) < 0) {
		fprintf(stderr, "Error forking: %s\n", strerror(errno));
		exit(5);
	} else if (srvpid == 0) {
		printf("Launching kismet_server: %s\n", eargv[0]);
		fflush(stdout);

		/* Dup over stdout/stderr so we can hijack the output */
		dup2(rpipe[1], STDOUT_FILENO);
		dup2(epipe[1], STDERR_FILENO);
		close(rpipe[0]);
		close(rpipe[1]);
		close(epipe[0]);
		close(epipe[1]);

		execv(eargv[0], eargv);

		fprintf(stderr, "Failed to launch %s: %s\n",
				eargv[0], strerror(errno));

		exit(255);
	} 

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

		tm.tv_sec = 0;
		tm.tv_usec = 500000;

		if (clipid > -1 &&
			wait4(clipid, NULL, WNOHANG, NULL) < 0) {
			break;
		}

		if (clipid == -1 &&
			wait4(srvpid, NULL, WNOHANG, NULL) < 0) {
			break;
		}

		if (select(max_fd + 1, &rset, NULL, NULL, &tm) < 0) {
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
					fflush(stdout);
					fflush(stderr);

					usleep(500000);

					execv(eargv[0], eargv);

					fprintf(stderr, "Failed to launch kismet_client\n");
					break;
				}

				fprintf(stderr, "Launched client, pid %d\n", clipid);
			}

			continue;
		}
	}

	wait4(clipid, NULL, 0, NULL);

	printf("\nKismet exiting...\n");

	kill(srvpid, SIGTERM);

	while (1) {
		FD_ZERO(&rset);

		FD_SET(rpipe[0], &rset);
		FD_SET(epipe[0], &rset);

		tm.tv_sec = 0;
		tm.tv_usec = 500000;

		if (select(max_fd + 1, &rset, NULL, NULL, &tm) < 0) {
			fprintf(stderr, "Select failed: %s\n", strerror(errno));
			break;
		}

		if (FD_ISSET(epipe[0], &rset)) {
			if (fgets(ret, 2048, err) == NULL ||
				feof(err)) {
				if (feof(out))
					break;
				continue;
			}

			if (clipid == -1) {
				fprintf(stderr, "%s", ret);
			} else {
				postcli_err.push_back(ret);
			}
		}

		if (FD_ISSET(rpipe[0], &rset)) {
			if (fgets(ret, 2048, out) == NULL ||
				feof(out)) {
				if (feof(err))
					break;

				continue;
			}

			fprintf(stdout, "%s", ret);
		}
	}

	for (unsigned int x = 0; x < postcli_err.size(); x++) {
		fprintf(stderr, "%s", postcli_err[x].c_str());
	}

	wait4(srvpid, NULL, 0, NULL);

	printf("Done.\n");
}


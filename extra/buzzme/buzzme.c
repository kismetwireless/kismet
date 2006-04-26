/*************************************************************************
 * $Header: /home/dragorn/src/CVS/kismet/kismet-devel/extra/buzzme/buzzme.c,v 1.1 2002/07/22 15:01:27 dragorn Exp $
 * buzzme.c - This program buzzes the Pizzio electric buzzer. I wrote
 *            this for use with Kismet. You can plug it into the
 *            /etc/kismet.conf to make sounds when kismet finds a network
 *            or finds a packet or a bad packet ...etc.
 *
 *            I couldn't make speaker make any other noises than one.
 *            I also don't know if saving state matters or not. Seems
 *            even volume doesn't change. Anyway, had to get creative
 *            vary number and length of beeps based on what otpion kismet
 *            passes in for what it found.
 *
 * Author :     Jim Murff (jmurff@pacbell.net)
 * Version:     1.1
 * Date   :     March 30, 2002
 * Last Update: April  1, 2002
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *
 * $Log: buzzme.c,v $
 * Revision 1.1  2002/07/22 15:01:27  dragorn
 * Initial revision
 *
 * Revision 1.3  2002/04/02 05:19:57  jmurff
 * fixed 'q' option.
 *
 * Revision 1.1  2002/04/02 01:15:28  jmurff
 * Initial revision
 *
 *
 *************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "sharp_char.h"


// MACRO
#define USEAGE(PROG) \
 fprintf(stdout,"\n  usage   : %s -hjnqt\n",PROG); \
 fprintf(stdout,"\n    Helper program for Kismet on the Zaurus.\n"); \
 fprintf(stdout,"    Make the Zaurus Pizzio Speaker buzz when\n"); \
 fprintf(stdout,"    Kismet calls this program with an option.\n"); \
 fprintf(stdout,"    see www.kismetwireless.net for more\n"); \
 fprintf(stdout,"    on Kismet.\n\n"); \
 fprintf(stdout,"  -n      : Sound for found Network. (%d beeps)\n",NEW_NETWORK); \
 fprintf(stdout,"  -t      : Sound for Traffic.       (%d beeps)\n",NETWORK_TRAFFIC); \
 fprintf(stdout,"  -j      : Sound for Junk Traffic.  (%d beeps)\n",JUNK_TRAFFIC); \
 fprintf(stdout,"  -q      : Do nothing just exit.    (DEFAULT)\n%s%s", \
	        "            Use this option to not play a \n", \
                "            specific sound.\n"); \
 fprintf(stdout,"  -h      : This Help Message\n\n"); \
 fprintf(stdout,"  %s\n\n",id);

#define BUZZER "/dev/sharp_buz"

// GLOBALS
static char id[] = "$Id: buzzme.c,v 1.1 2002/07/22 15:01:27 dragorn Exp $";
enum {
  NEW_NETWORK     =  3,
  NETWORK_TRAFFIC =  2,
  JUNK_TRAFFIC    =  1,
  NOOP            = 99
};

//************** Code Starts *****************
int
main(int argc, char **argv)
{
  int fd, i;
  int bflag, ch, flag = NOOP;
  sharp_buzzer_status zbs;
  sharp_buzzer_status zbs_save;
  char *progname = argv[0];
  char pname[64];
  extern char *optarg;
  extern int optind;

  // Figure out program name. Remove path if needed.
  strncpy(pname,argv[0],sizeof(pname));
  pname[sizeof(pname)-1] = '\0';
  if ((progname = rindex(pname,'/')) != NULL) {
     progname++; // skip slash.
  }
  else
    progname = pname;

  // Parse Options.
  bflag = 0;
  while ((ch = getopt(argc, argv, "ntjqh")) != -1) {
        switch(ch) {
        case 'n':
          flag = NEW_NETWORK;
          break;

        case 't':
          flag = NETWORK_TRAFFIC;
          break;

        case 'j':
          flag = JUNK_TRAFFIC;
          break;

        case 'q':
        default:
          // Do nothing.
          flag = NOOP;
          break;

        case 'h':
          USEAGE(progname);
          exit(-1);
          break;
        } // switch
  } //while
  argc -= optind;
  argv += optind;

  if (flag == NOOP)
    exit(0);

  // Open the Buzzer
  if ((fd = open (BUZZER, O_RDWR|O_NONBLOCK)) == -1) {
      perror("Device Open Error");
      fprintf (stderr, "\n%s:%s: Problems opening device '%s'.\n\n",
               progname,__FUNCTION__, BUZZER);
      exit(1);
  }

  // Save old setting (don't know if need it)
  zbs_save.which =  SHARP_BUZ_SCHEDULE_ALARM;
  if (ioctl(fd, SHARP_BUZZER_GETVOLUME, &zbs_save) == -1) {
      perror("Error Getting Buzzer Volume");
      fprintf (stderr, "\n%s:%s: Problems getting volume on device '%s'.\n\n",
               progname,__FUNCTION__, BUZZER);
      exit(2);
  }

  // Set new volume
  zbs.which =  SHARP_BUZ_SCHEDULE_ALARM;
  zbs.volume = SHARP_BUZ_VOLUME_LOW;
  zbs.mute = 0;
  if (ioctl(fd, SHARP_BUZZER_SETVOLUME, &zbs) == -1) {
      perror("Error Setting Buzzer Volume");
      fprintf (stderr, "\n%s:%s: Problems setting volume on device '%s'.\n\n",
               progname,__FUNCTION__, BUZZER);
      exit(3);
  }

  for(i = 0; i < flag; i++) {
    // Make the Sound
    if (ioctl(fd, SHARP_BUZZER_MAKESOUND,SHARP_BUZ_SCHEDULE_ALARM) == -1) {
      perror("Error Making Sound");
      fprintf (stderr, "\n%s:%s: Problems making sound on device '%s'.\n\n",
               progname,__FUNCTION__, BUZZER);
      exit(4);
    }
    usleep(500);
  }
  
  // reset to saved value.	
  if (ioctl(fd, SHARP_BUZZER_SETVOLUME, &zbs_save) == -1) {
      perror("Error Resetting Buzzer Volume");
      fprintf (stderr, "\n%s:%s: Problems reseting volume on device '%s'.\n\n",
               progname,__FUNCTION__, BUZZER);
      exit(5);
  }

  // Clean up.
  close(fd);

  exit(0);

} // end main


/*
 *  linux/include/asm/sharp_char.h
 *
 * sharp drivers definitions (SHARP)
 *
 * Copyright (C) 2001  SHARP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Change Log
 */

#ifndef __ASM_SHARP_CHAR_H_INCLUDED
#define __ASM_SHARP_CHAR_H_INCLUDED

/*
 *  If  SHARPCHAR_USE_MISCDEV defined , misc driver architecture used instead of sharp_char
 */

#define SHARPCHAR_USE_MISCDEV

/*
 *  devices defines...
 */

#ifndef SHARP_DEV_MAJOR
#define SHARP_DEV_MAJOR  11
#endif

#ifndef SHARP_DEV_MINOR_START
#define SHARP_DEV_MINOR_START 210
#endif

#define SHARP_DEV_MINOR_MAX   4  /* defines last minor number of SHARP device */

#define SHARP_LED_MINOR          (SHARP_DEV_MINOR_START+0)
#define SHARP_BUZZER_MINOR       (SHARP_DEV_MINOR_START+1)
#define SHARP_GSM_MINOR          (SHARP_DEV_MINOR_START+2)
#define SHARP_AUDIOCTL_MINOR     (SHARP_DEV_MINOR_START+3)
#define SHARP_KBDCTL_MINOR       (SHARP_DEV_MINOR_START+4)

/*
 *  ioctl defines...
 */

#define SHARP_DEV_IOCTL_COMMAND_START 0x5680

/* --- for SHARP_LED device --- */
#define	SHARP_LED_IOCTL_START (SHARP_DEV_IOCTL_COMMAND_START)
#define SHARP_LED_GETSTATUS   (SHARP_LED_IOCTL_START)
#define SHARP_LED_SETSTATUS   (SHARP_LED_IOCTL_START+1)
#define SHARP_LED_ISUPPORTED  (SHARP_LED_IOCTL_START+2)

typedef struct sharp_led_status {
  int which;   /* select which LED status is wanted. */
  int status;  /* set new led status if you call SHARP_LED_SETSTATUS */
} sharp_led_status;

#define SHARP_LED_WHICH_MAX   15       /* last number of LED */

/* parameters for 'which' member */
#define SHARP_LED_PDA          0       /* PDA status */
#define SHARP_LED_DALARM       1       /* daily alarm */
#define SHARP_LED_SALARM       2       /* schedule alarm */
#define SHARP_LED_BATTERY      3       /* main battery status */
#define SHARP_LED_ACSTATUS     4       /* AC line status */
#define SHARP_LED_CHARGER      5       /* charger status */
#define SHARP_LED_PHONE_RSSI   6       /* phone status (RSSI...) */
#define SHARP_LED_PHONE_DIAL   7       /* phone status (dialing...) */
#define SHARP_LED_PHONE_IN     8       /* phone status (incoming..) */
#define SHARP_LED_MAIL_EXISTS  9       /* mail status (exists or not) */
#define SHARP_LED_MAIL_SEND    10      /* mail status (sending...) */
#define SHARP_LED_MAIL_QUEUE   11      /* mail to send is in queue */
#define SHARP_LED_COLLIE_0     12      /* 1st pri. battery LED control */
#define SHARP_LED_COLLIE_1     13      /* 1st pri. mail LED control */
#define SHARP_LED_COMM         14      /* communication status */
#define SHARP_LED_BROWSER      15      /* WWW browser status */

/* parameters for 'status' member */
#define LED_PDA_RUNNING          0   /* for SHARP_LED_RUN */
#define LED_PDA_SUSPENDED        1   /* for SHARP_LED_RUN */
#define LED_PDA_OFF              2   /* for SHARP_LED_RUN */
#define LED_PDA_ERROR            3   /* for SHARP_LED_RUN */

#define LED_DALARM_OFF           0   /* for SHARP_LED_DALARM */
#define LED_DALARM_ON            1   /* for SHARP_LED_DALARM */

#define LED_SALARM_OFF           0   /* for SHARP_LED_SALARM */
#define LED_SALARM_ON            1   /* for SHARP_LED_SALARM */

#define LED_BATTERY_GOOD         0   /* for SHARP_LED_BATTERY */
#define LED_BATTERY_LOW          1   /* for SHARP_LED_BATTERY */
#define LED_BATTERY_VERY_LOW     2   /* for SHARP_LED_BATTERY */
#define LED_BATTERY_CRITICAL     3   /* for SHARP_LED_BATTERY */

#define LED_CHARGER_OFF          0   /* for SHARP_LED_CHARGER */
#define LED_CHARGER_CHARGING     1   /* for SHARP_LED_CHARGER */
#define LED_CHARGER_ERROR        2   /* for SHARP_LED_CHARGER */

#define LED_AC_NOT_CONNECTED     0   /* for SHARP_LED_ACSTATUS */
#define LED_AC_CONNECTED         1   /* for SHARP_LED_ACSTATUS */

#define LED_RSSI_OUT             0   /* for SHARP_LED_PHONE_RSSI */
#define LED_RSSI_IN              1   /* for SHARP_LED_PHONE_RSSI */

#define LED_DIAL_OFF             0   /* for SHARP_LED_PHONE_DIAL */
#define LED_DIAL_DIALING         1   /* for SHARP_LED_PHONE_DIAL */
#define LED_DIAL_HOLDING         2   /* for SHARP_LED_PHONE_DIAL */

#define LED_PHONE_WAITING        0   /* for SHARP_LED_PHONE_IN */
#define LED_PHONE_INCOMING       1   /* for SHARP_LED_PHONE_IN */

#define LED_MAIL_NO_UNREAD_MAIL  0   /* for SHARP_LED_MAIL_EXISTS */
#define LED_MAIL_NEWMAIL_EXISTS  1   /* for SHARP_LED_MAIL_EXISTS */
#define LED_MAIL_UNREAD_MAIL_EX  2   /* for SHARP_LED_MAIL_EXISTS */

#define LED_SENDMAIL_OFF         0   /* for SHARP_LED_MAIL_SEND */
#define LED_SENDMAIL_SENDING     1   /* for SHARP_LED_MAIL_SEND */
#define LED_SENDMAIL_ERROR       2   /* for SHARP_LED_MAIL_SEND */

#define LED_MAILQUEUE_NOUNREAD   0   /* for SHARP_LED_MAIL_QUEUE */
#define LED_MAILQUEUE_NEWMAIL    1   /* for SHARP_LED_MAIL_QUEUE */
#define LED_MAILQUEUE_UNREAD     2   /* for SHARP_LED_MAIL_QUEUE */

#define LED_COLLIE_0_DEFAULT	 0   /* for SHARP_LED_COLLIE_0 */
#define LED_COLLIE_0_OFF         1   /* for SHARP_LED_COLLIE_0 */
#define LED_COLLIE_0_ON		 2   /* for SHARP_LED_COLLIE_0 */
#define LED_COLLIE_0_FASTBLINK	 3   /* for SHARP_LED_COLLIE_0 */
#define LED_COLLIE_0_SLOWBLINK	 4   /* for SHARP_LED_COLLIE_0 */

#define LED_COLLIE_1_DEFAULT     0   /* for SHARP_LED_COLLIE_1 */
#define LED_COLLIE_1_OFF         1   /* for SHARP_LED_COLLIE_1 */
#define LED_COLLIE_1_ON          2   /* for SHARP_LED_COLLIE_1 */
#define LED_COLLIE_1_FLASHON     3   /* for SHARP_LED_COLLIE_1 */
#define LED_COLLIE_1_FLASHOFF    4   /* for SHARP_LED_COLLIE_1 */
#define LED_COLLIE_1_VFSTBLINK   5   /* for SHARP_LED_COLLIE_1 */
#define LED_COLLIE_1_FASTBLINK   6   /* for SHARP_LED_COLLIE_1 */
#define LED_COLLIE_1_NORMBLINK   7   /* for SHARP_LED_COLLIE_1 */
#define LED_COLLIE_1_SLOWBLINK   8   /* for SHARP_LED_COLLIE_1 */
#define LED_COLLIE_1_SOFTBLINK   9   /* for SHARP_LED_COLLIE_1 */
#define LED_COLLIE_1_SOFTFLASH   10  /* for SHARP_LED_COLLIE_1 */

#define LED_COMM_OFFLINE         0   /* for SHARP_LED_COMM */
#define LED_COMM_ONLINE          1   /* for SHARP_LED_COMM */
#define LED_COMM_ERROR           2   /* for SHARP_LED_COMM */

#define LED_BROWSER_OFFLINE      0   /* for SHARP_LED_BROWSER */
#define LED_BROWSER_ONLINE       1   /* for SHARP_LED_BROWSER */
#define LED_BROWSER_ERROR        2   /* for SHARP_LED_BROWSER */


/* --- for SHARP_BUZZER device --- */
#define	SHARP_BUZZER_IOCTL_START (SHARP_DEV_IOCTL_COMMAND_START)
#define SHARP_BUZZER_MAKESOUND   (SHARP_BUZZER_IOCTL_START)
#define SHARP_BUZZER_SETVOLUME   (SHARP_BUZZER_IOCTL_START+1)
#define SHARP_BUZZER_GETVOLUME   (SHARP_BUZZER_IOCTL_START+2)
#define SHARP_BUZZER_ISSUPPORTED (SHARP_BUZZER_IOCTL_START+3)
#define SHARP_BUZZER_SETMUTE     (SHARP_BUZZER_IOCTL_START+4)
#define SHARP_BUZZER_STOPSOUND   (SHARP_BUZZER_IOCTL_START+5)
#define SHARP_BUZZER_SET_BUFFER  (SHARP_BUZZER_IOCTL_START+6)

typedef struct sharp_buzzer_status { /* this struct is used for setvolume/getvolume */
  int which;     /* select which LED status is wanted. */
  int volume;    /* set new buzzer volume if you call SHARP_BUZZER_SETVOLUME */
  int mute;      /* set 1 to MUTE if you call SHARP_BUZZER_SETMUTE */
} sharp_buzzer_status;

#define SHARP_BUZ_WHICH_MAX       14  /* last number of buzzer */

#define SHARP_BUZ_ALL_SOUNDS      -1  /* for setting volumes of ALL sounds at a time */

#define SHARP_BUZ_WRITESOUND       0  /* for sound datas through 'write' calls */
#define SHARP_BUZ_TOUCHSOUND       1  /* touch panel sound */
#define SHARP_BUZ_KEYSOUND         2  /* key sound */
#define SHARP_PDA_ILLCLICKSOUND    3  /* illegal click */
#define SHARP_PDA_WARNSOUND        4  /* warning occurred */
#define SHARP_PDA_ERRORSOUND       5  /* error occurred */
#define SHARP_PDA_CRITICALSOUND    6  /* critical error occurred */
#define SHARP_PDA_SYSSTARTSOUND    7  /* system start */
#define SHARP_PDA_SYSTEMENDSOUND   8  /* system shutdown */
#define SHARP_PDA_APPSTART         9  /* application start */
#define SHARP_PDA_APPQUIT         10  /* application ends */
#define SHARP_BUZ_SCHEDULE_ALARM  11  /* schedule alarm */
#define SHARP_BUZ_DAILY_ALARM     12  /* daily alarm */
#define SHARP_BUZ_GOT_PHONE_CALL  13  /* phone call sound */
#define SHARP_BUZ_GOT_MAIL        14  /* mail sound */

#define SHARP_BUZ_VOLUME_OFF       0
#define SHARP_BUZ_VOLUME_LOW       33
#define SHARP_BUZ_VOLUME_MEDIUM    67
#define SHARP_BUZ_VOLUME_HIGH      100  /* currentry , this is the maximum ... */
#define SHARP_BUZ_VOLUME_MAX       (SHARP_BUZ_VOLUME_HIGH)

/* --- for SHARP_GSM device --- */
#define	SHARP_GSM_IOCTL_START     (SHARP_DEV_IOCTL_COMMAND_START)
#define SHARP_GSM_GETEXTSTATUS    (SHARP_GSM_IOCTL_START+16)
#define SHARP_GSM_INFO_TELL_MODE  (SHARP_GSM_IOCTL_START+17)
#define SHARP_IRIS_GETSYNCSTATUS  (SHARP_GSM_IOCTL_START+18)
#define SHARP_IRIS_RECHECKDEVICE  (SHARP_GSM_IOCTL_START+19)


#define GSM_PHONE_NO_POWER          0 /* for SHARP_GSM_INFO_TELL_MODE */
#define GSM_PHONE_NO_CONNECTION     1 /* for SHARP_GSM_INFO_TELL_MODE */
#define GSM_PHONE_IN_ANALOG_MODE    2 /* for SHARP_GSM_INFO_TELL_MODE */
#define GSM_PHONE_IN_DATA_MODE      3 /* for SHARP_GSM_INFO_TELL_MODE */

#define IRIS_AUDIO_EXT_IS_NONE          0
#define IRIS_AUDIO_EXT_IS_HEADPHONEMIC  1
#define IRIS_AUDIO_EXT_IS_EXTSPEAKER    2

typedef struct sharp_gsmext_status {
  int carkit;         /* be set as 1 , if car-kit is connected */
  int headphone_mic;  /* be set as 1 , if head-phone-microphone is inserted */
  int external_sp;    /* be set as 1 , if external-speaker is inserted */
} sharp_gsmext_status;

typedef struct sharp_irisext_status {  /* for SHARP_IRIS_GETSYNCSTATUS */
  int usb;
  int uart;
  int carkit;
} sharp_irisext_status;

/* --- for SHARP_AUDIOCTL device --- */
#define	SHARP_AUDIOCTL_IOCTL_START          (SHARP_DEV_IOCTL_COMMAND_START)
#define	SHARP_AUDIOCTL_ARCH_IOCTL_START     (SHARP_DEV_IOCTL_COMMAND_START+0x10)
#define SHARP_IRIS_AUFIL_GETVAL             (SHARP_AUDIOCTL_ARCH_IOCTL_START+0)
#define SHARP_IRIS_AUFIL_SETVAL             (SHARP_AUDIOCTL_ARCH_IOCTL_START+1)
#define SHARP_IRIS_AMP_EXT_ON               (SHARP_AUDIOCTL_ARCH_IOCTL_START+2)
#define SHARP_IRIS_AMP_EXT_OFF              (SHARP_AUDIOCTL_ARCH_IOCTL_START+3)


#define SHARP_IRIS_AUFIL_FILTERON   0x01    /* Iris AudioCtl Specific. Enable Audio Filter */

/* --- for SHARP_AUDIOCTL device --- */
#define	SHARP_KBDCTL_IOCTL_START            (SHARP_DEV_IOCTL_COMMAND_START)
#define SHARP_KBDCTL_GETMODIFSTAT           (SHARP_KBDCTL_IOCTL_START+0)
#define SHARP_KBDCTL_TOGGLEMODIFSTAT        (SHARP_KBDCTL_IOCTL_START+1)
#define SHARP_KBDCTL_SETHOLDTH              (SHARP_KBDCTL_IOCTL_START+2)
#define SHARP_KBDCTL_SETHOLDTH_GR           (SHARP_KBDCTL_IOCTL_START+3)
#define SHARP_KBDCTL_HOLDINFO_SETHD         (SHARP_KBDCTL_IOCTL_START+4)
#define SHARP_KBDCTL_HOLDINFO_SETSL         (SHARP_KBDCTL_IOCTL_START+5)
#define SHARP_KBDCTL_HOLDINFO_DELHD         (SHARP_KBDCTL_IOCTL_START+6)
#define SHARP_KBDCTL_HOLDINFO_DELSL         (SHARP_KBDCTL_IOCTL_START+7)
#define SHARP_KBDCTL_HOLDINFO_RESTHD        (SHARP_KBDCTL_IOCTL_START+8)
#define SHARP_KBDCTL_HOLDINFO_RESTSL        (SHARP_KBDCTL_IOCTL_START+9)
#define SHARP_KBDCTL_HOLDINFO_RESTFULL      (SHARP_KBDCTL_IOCTL_START+10)
#define IRIS_KBDCTL_ENABLEKEYBOARD          (SHARP_KBDCTL_IOCTL_START+16)
#define IRIS_KBDCTL_DISABLEKEYBOARD         (SHARP_KBDCTL_IOCTL_START+17)

typedef struct sharp_kbdctl_modifstat {
  int which;
  int stat;
} sharp_kbdctl_modifstat;

typedef struct sharp_kbdctl_holdstat {
  int group;
  int timeout;
} sharp_kbdctl_holdstat;

typedef struct sharp_kbdctl_holdcustom {
  int normal_hardcode;
  int normal_slcode;
  int hold_slcode;
} sharp_kbdctl_holdcustom;

#define SHARP_EXTMODIF_2ND      0x01
#define SHARP_EXTMODIF_CAPS     0x02
#define SHARP_EXTMODIF_NUMLOCK  0x03

#define HOLDKEY_GROUP_NORMAL  0
#define HOLDKEY_GROUP_POWER   1

#endif /* __ASM_SHARP_CHAR_H_INCLUDED */


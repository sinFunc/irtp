/***************************************************************************
* config.h.cmake
* Copyright (C) 2014  Belledonne Communications, Grenoble France
*
****************************************************************************
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
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*
****************************************************************************/

#define ORTP_MAJOR_VERSION 5
#define ORTP_MINOR_VERSION 2
#define ORTP_MICRO_VERSION 64
#define ORTP_VERSION "5.2.64"

#define HAVE_SYS_UIO_H 1
/* #undef HAVE_SYS_AUDIO_H */
#define HAVE_SYS_SHM_H 1
#define HAVE_ATOMIC 1
/* #undef HAVE_ARC4RANDOM */
#define HAVE_RECVMSG 1
#define HAVE_SENDMSG 1

/* #undef ORTP_BIGENDIAN */

/* #undef PERF */
/* #undef ORTP_TIMESTAMP */
/* #undef ORTP_DEBUG_MODE */
/* #undef ORTP_DEFAULT_THREAD_STACK_SIZE */
#define POSIXTIMER_INTERVAL 10000
/* #undef __APPLE_USE_RFC_3542 */

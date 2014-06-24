
/***************************************************************************
 * nsock_scan.cc -- Nmap's connect() scan implemented using nsock library.
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2013 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "nsock_scan.h"
#include "nmap_error.h"
#include "NmapOps.h"

extern NmapOps o;

class NsockProbe {
public:
  Target *target;
  unsigned short portno;
  u8 tryno;
};

bool send_next_probe();
void make_connection(Target *target, unsigned short portno, int tryno);

std::vector<Target *>::iterator next_target;
std::vector<Target *> Targets;
int current_port_idx;
u16 *portarray;
int numports;
nsock_pool mypool;
int max_tryno = 1;

/* Handles a scheduled probe timer. For more details, see the definition. */
void scheduled_probe_callback(nsock_pool nsp, nsock_event evt, void *data);

/* nsock_connect_* callback. This is where we the connect() result is
   interpreted and new probes are scheduled. */
void connect_handler(nsock_pool nsp, nsock_event evt, void *data)
{
  enum nse_status status = nse_status(evt);
  enum nse_type type = nse_type(evt);
  nsock_iod nsi = nse_iod(evt);

  assert(type == NSE_TYPE_CONNECT);

  /* Extract the pointer to the probe and target from the event arguments. */
  NsockProbe *probe = (NsockProbe *)data;
  Target *target = probe->target;

  int reason_id;

  /* A lot of further behavior depends on the event's status. First, let's see
     if it's some kind of an error and if so, which one... */
  if (status == NSE_STATUS_ERROR) {
    target->ports.setPortState(probe->portno, IPPROTO_TCP, PORT_CLOSED);
    int connect_errno = nse_errorcode(evt);
    switch (connect_errno) {
      /* This can happen on localhost, successful/failing connection
         immediately in non-blocking mode. */
    case ECONNREFUSED:
      reason_id = ER_CONREFUSED;
      break;
    case ENETUNREACH:
      if (o.debugging)
        log_write(LOG_STDOUT, "Got ENETUNREACH from %s connect()\n", __func__);
      reason_id = ER_NETUNREACH;
      break;
    case EACCES:
      if (o.debugging)
        log_write(LOG_STDOUT, "Got EACCES from %s connect()\n", __func__);
      reason_id = ER_ACCES;
      break;
    default:
      /* TODO: ultra_scan.cc checks for connecterror and if it's false, reports
               a debug message here. Perhaps it's possible here as well? */
      reason_id = ER_UNKNOWN;
    }

  /* Handle the TCP connection timeout. For now we just assume that it's
     dropped by the firewall, not congestion. */
  } else if (status == NSE_STATUS_TIMEOUT) {
    target->ports.setPortState(probe->portno, IPPROTO_TCP, PORT_FILTERED);
    reason_id = ER_NORESPONSE;

  /* We managed to connect! */
  } else {
    assert(status == NSE_STATUS_SUCCESS);
    target->ports.setPortState(probe->portno, IPPROTO_TCP, PORT_OPEN);
    reason_id = ER_SYNACK;
  }

  target->ports.setStateReason(probe->portno, IPPROTO_TCP, reason_id, 0, NULL);

  /* Close the socket immediately and get rid of the probe. */
  nsi_delete(nsi, NSOCK_PENDING_NOTIFY);

  if (status != NSE_STATUS_TIMEOUT) {
    /* If this was either a closed or open port, just go on. */
    send_next_probe();
  } else {
    /* Otherwise, let's see if we can retry the probe to make sure it's
       filtered. */
    if (probe->tryno < max_tryno + 1) {
      if (o.debugging)
        log_write(LOG_STDOUT, "Retrying the probe to %s:%d\n",
                  probe->target->targetipstr(), probe->portno);
      make_connection(probe->target, probe->portno, probe->tryno + 1);
    } else {
      /* We can't retry the probe, so let's send next "normal" probe to keep
         the number of outstanding probes. */
      if (o.verbose)
         log_write(LOG_STDOUT, "Giving up on %s:%d\n",
                  probe->target->targetipstr(), probe->portno);
      send_next_probe();
    }
  }
  delete probe;
}

/* Start a nsock connection to the given target on a given port. */
void make_connection(Target *target, unsigned short portno, int tryno) {

  /* Translate target's IP to struct sockaddr_storage. */
  struct sockaddr_storage targetss;
  size_t targetsslen;
  nsock_iod sock_nsi = nsi_new(mypool, NULL);
  if (sock_nsi == NULL)
    fatal("Failed to create nsock_iod.");
  if (nsi_set_hostname(sock_nsi, target->targetipstr()) == -1)
    fatal("Failed to set hostname on iod.");
  if (target->TargetSockAddr(&targetss, &targetsslen) != 0)
    fatal("Failed to get target socket address in %s", __func__);

  /* Prepare NsockProbe and run nsock_connect_tcp. */
  NsockProbe *probe = new NsockProbe();
  probe->target = target;
  probe->portno = portno;
  probe->tryno = tryno;
  nsock_connect_tcp(mypool, sock_nsi, connect_handler,
                    1000, /* timeout */
                    (void *)probe,
                    (struct sockaddr *)&targetss, targetsslen,
                    portno);
}

/* An interface that can be used to schedule a particular probe after a given
   number of miliseconds passed. */
void schedule_probe(int msecs, Target *target, unsigned short portno) {
  NsockProbe *probe = new NsockProbe();
  probe->target = target;
  probe->portno = portno;
  nsock_timer_create(mypool, scheduled_probe_callback, msecs, probe);
}

/* Handles a scheduled probe timer. This is the timer callback for
   schedule_probe. */
void scheduled_probe_callback(nsock_pool nsp, nsock_event evt, void *data) {
  assert(nse_status(evt) == NSE_STATUS_SUCCESS);
  NsockProbe *probe = (NsockProbe *)data;
  make_connection(probe->target, probe->portno, 0);
}

/* Fires another probe. Returns false if all probes were sent. */
bool send_next_probe() {

  if (next_target == Targets.end()) {
    current_port_idx++;
    if (current_port_idx >= numports) {
      return false;
    }
    next_target = Targets.begin();
  }

  unsigned short portno = portarray[current_port_idx];
  Target *target = *next_target;
  next_target++;
  make_connection(target, portno, 0);
  return true;
}

static inline int get_max_parallelism() {
  return o.max_parallelism ? o.max_parallelism : 300;
}

/* Main scanning function. Schedules the first probes and runs the nsock
   main loop. */
void nsock_scan(std::vector<Target *> &Targets_arg, u16 *portarray_arg, int numports_arg) {

  int scanning_now_count = 0;

  if (o.debugging)
    log_write(LOG_STDOUT, "nsock_scan() begins.\n");

  /* Initialize the global variables. Maybe I should move these to a new
     NsockScanInfo class and make its instance global instead? */
  portarray = portarray_arg;
  numports = numports_arg;
  Targets = Targets_arg;

  /* Initialize the Nsock pool. */
  mypool = nsp_new(NULL);
  if (mypool == NULL)
    fatal("Failed to create nsock_pool.");

  /* Schedule the first probes. Setting current_port_idx to -1 and next_target
     to Targets.end() will force a reset in the next send_next_probe() call. */
  current_port_idx = -1;
  next_target = Targets.end();
  while(true) {
    if (scanning_now_count < get_max_parallelism()) {
      scanning_now_count++;
      if(!send_next_probe())
        break;
    } else
      break;
  }

  /* Jump into the main loop. Handle any unexpected errors. */
  enum nsock_loopstatus looprc = nsock_loop(mypool, -1);
  if (looprc == NSOCK_LOOP_ERROR) {
    int err = nsp_geterrorcode(mypool);
    fatal("nsock_scan: unexpected nsock_loop error.  Error code %d (%s)", err,
          socket_strerror(err));
  }

  /* The main loop is done and so is nsock_scan. Destroy the pool. */
  nsp_delete(mypool);
}


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

struct target_port_pair {
  Target *target;
  unsigned short portno;
};

bool handle_next_host();

std::vector<Target *>::iterator current_target;
std::vector<Target *> Targets;
int current_port_idx;
u16 *portarray;
int numports;
nsock_pool mypool;
int scanning_now_count = 0;

void connect_handler(nsock_pool nsp, nsock_event evt, void *data)
{
  scanning_now_count--;

  enum nse_status status = nse_status(evt);
  enum nse_type type = nse_type(evt);
  nsock_iod nsi = nse_iod(evt);

  assert(type == NSE_TYPE_CONNECT);

  struct target_port_pair *target_port_pair = (struct target_port_pair *)data;
  Target *target = target_port_pair->target;

  int reason_id;

  if (status == NSE_STATUS_ERROR) {
    target->ports.setPortState(target_port_pair->portno, IPPROTO_TCP,
                               PORT_CLOSED);
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
  } else if (status == NSE_STATUS_TIMEOUT) {
    target->ports.setPortState(target_port_pair->portno, IPPROTO_TCP,
                               PORT_FILTERED);
    reason_id = ER_NORESPONSE;
  } else {
    assert(status == NSE_STATUS_SUCCESS);
    target->ports.setPortState(target_port_pair->portno, IPPROTO_TCP,
                               PORT_OPEN);
    reason_id = ER_SYNACK;
  }

  target->ports.setStateReason(target_port_pair->portno, IPPROTO_TCP,
                               reason_id, 0, NULL);

  nsi_delete(nsi, NSOCK_PENDING_NOTIFY);

  free(target_port_pair);

  handle_next_host();
}

void make_connection(Target *target, unsigned short portno) {
  const char *t = (const char *)target->v4hostip();
  char targetstr[20];
  struct sockaddr_storage targetss;
  size_t targetsslen;
  struct target_port_pair *target_port_pair =
    (struct target_port_pair *)safe_malloc(sizeof(struct target_port_pair));

  Snprintf(targetstr, 20, "%d.%d.%d.%d", UC(t[0]), UC(t[1]),
                                         UC(t[2]), UC(t[3]));

  nsock_iod sock_nsi = nsi_new(mypool, NULL);
  if (sock_nsi == NULL)
    fatal("Failed to create nsock_iod.");
  if (nsi_set_hostname(sock_nsi, targetstr) == -1)
    fatal("Failed to set hostname on iod.");
  if (target->TargetSockAddr(&targetss, &targetsslen) != 0)
    fatal("Failed to get target socket address in %s", __func__);

  target_port_pair->target = target;
  target_port_pair->portno = portno;
  nsock_connect_tcp(mypool, sock_nsi, connect_handler,
                    1000, /* timeout */
                    (void *)target_port_pair,
                    (struct sockaddr *)&targetss, targetsslen,
                    portno);
}

void sleep_callback(nsock_pool nsp, nsock_event evt, void *data) {
  assert(nse_status(evt) == NSE_STATUS_SUCCESS);
  struct target_port_pair *target_port_pair = (struct target_port_pair *)data;
  make_connection(target_port_pair->target, target_port_pair->portno);
}

void schedule_scan(int msecs, Target *target, unsigned short portno) {
  struct target_port_pair *target_port_pair =
    (struct target_port_pair *)safe_malloc(sizeof(struct target_port_pair));

  target_port_pair->target = target;
  target_port_pair->portno = portno;
  nsock_timer_create(mypool, sleep_callback, msecs, target_port_pair);
}

bool handle_next_host() {

  if (current_target == Targets.end()) {
    current_port_idx++;
    if (current_port_idx >= numports) {
      return false;
    }
    current_target = Targets.begin();
  }

  unsigned short portno = portarray[current_port_idx];
  Target *target = *current_target;
  make_connection(target, portno);
  current_target++;
  return true;
}

static inline int get_max_parallelism() {
  return o.max_parallelism ? o.max_parallelism : 300;
}

void nsock_scan(std::vector<Target *> &Targets_arg, u16 *portarray_arg, int numports_arg) {

  if (o.debugging)
    log_write(LOG_STDOUT, "nsock_scan() begins.\n");

  portarray = portarray_arg;
  numports = numports_arg;
  Targets = Targets_arg;
  scanning_now_count = 0;

  mypool = nsp_new(NULL);
  if (mypool == NULL)
    fatal("Failed to create nsock_pool.");

  current_port_idx = -1;
  current_target = Targets.end();
  while(true) {
    if (scanning_now_count < get_max_parallelism()) {
      scanning_now_count++;
      if(!handle_next_host())
        break;
    } else
      break;
  }

  enum nsock_loopstatus looprc = nsock_loop(mypool, -1);
  if (looprc == NSOCK_LOOP_ERROR) {
    int err = nsp_geterrorcode(mypool);
    fatal("nsock_scan: unexpected nsock_loop error.  Error code %d (%s)", err, socket_strerror(err));
  }

  nsp_delete(mypool);
}

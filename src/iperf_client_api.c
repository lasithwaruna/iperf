/*
 * iperf, Copyright (c) 2014-2021, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include "iperf.h"
#include "iperf_api.h"
#include "iperf_util.h"
#include "iperf_locale.h"
#include "iperf_time.h"
#include "net.h"
#include "timer.h"

#if defined(HAVE_TCP_CONGESTION)
#if !defined(TCP_CA_NAME_MAX)
#define TCP_CA_NAME_MAX 16
#endif /* TCP_CA_NAME_MAX */
#endif /* HAVE_TCP_CONGESTION */

int
iperf_create_streams(struct iperf_test *test, int sender)
{

    return 0;
}

static void
test_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{
  
}

static void
client_stats_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{
  
}

static void
client_reporter_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{
 
}

static int
create_client_timers(struct iperf_test * test)
{

}

static void
client_omit_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{

}

static int
create_client_omit_timer(struct iperf_test * test)
{

}

int
iperf_handle_message_client(struct iperf_test *test)
{


    return 0;
}



/* iperf_connect -- client to server connection function */
int
iperf_connect(struct iperf_test *test)
{


    return 0;
}


int
iperf_client_end(struct iperf_test *test)
{
  
    return 0;
}


int
iperf_run_client(struct iperf_test * test)
{
    return 0;   // Return 0 and not -1 since all terminating function were done here.
                // Also prevents error message logging outside the already closed JSON output.
}

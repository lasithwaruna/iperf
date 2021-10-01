/*
 * iperf, Copyright (c) 2014-2021 The Regents of the University of
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
/* iperf_server_api.c: Functions to be used by an iperf server
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/time.h>
#include <sys/resource.h>
#include <sched.h>
#include <setjmp.h>

#include "iperf.h"
#include "iperf_api.h"
#include "iperf_udp.h"
#include "iperf_tcp.h"
#include "iperf_util.h"
#include "timer.h"
#include "iperf_time.h"
#include "net.h"
#include "units.h"
#include "iperf_util.h"
#include "iperf_locale.h"

#if defined(HAVE_TCP_CONGESTION)
#if !defined(TCP_CA_NAME_MAX)
#define TCP_CA_NAME_MAX 16
#endif /* TCP_CA_NAME_MAX */
#endif /* HAVE_TCP_CONGESTION */

int
iperf_server_listen(struct iperf_master_test *test)
{
    retry:
    if((test->listener = netannounce(test->settings->domain, Ptcp, test->bind_address, test->bind_dev, test->server_port)) < 0) {
	if (errno == EAFNOSUPPORT && (test->settings->domain == AF_INET6 || test->settings->domain == AF_UNSPEC)) {
	    /* If we get "Address family not supported by protocol", that
	    ** probably means we were compiled with IPv6 but the running
	    ** kernel does not actually do IPv6.  This is not too unusual,
	    ** v6 support is and perhaps always will be spotty.
	    */
	    warning("this system does not seem to support IPv6 - trying IPv4");
	    test->settings->domain = AF_INET;
	    goto retry;
	} else {
	    i_errno = IELISTEN;
	    return -1;
	}
    }
    if (!test->json_output) {
        if (test->server_last_run_rc != 2)
            test->server_test_number +=1;
        if (test->debug || test->server_last_run_rc != 2) {
  
	    iperf_printf_master(test, "-----------------------------------------------------------\n");
	    iperf_printf_master(test, "Server listening on %d (test #%d)\n", test->server_port, test->server_test_number);
	    iperf_printf_master(test, "-----------------------------------------------------------\n");
	    if (test->forceflush)
	        iflush(test);
        }
    }

    FD_ZERO(&test->read_set);
    FD_ZERO(&test->write_set);
    FD_SET(test->listener, &test->read_set);
    if (test->listener > test->max_fd) test->max_fd = test->listener;

    return 0;
}

int
iperf_accept(struct iperf_master_test *master_test)
{

    int s;
    int isNewTest = 1;
    signed char rbuf = ACCESS_DENIED;
    socklen_t len;
    struct sockaddr_storage addr;

    len = sizeof(addr);
    if ((s = accept(master_test->listener, (struct sockaddr *) &addr, &len)) < 0) {
        i_errno = IEACCEPT;
        return -1;
    }

    master_test->current_sck = s;
   
    // set TCP_NODELAY for lower latency on control messages
    int flag = 1;
    if (setsockopt(master_test->current_sck, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int))) {
        i_errno = IESETNODELAY;
        return -1;
    }

    if (Nread(master_test->current_sck, master_test->current_cookie, COOKIE_SIZE, Ptcp) < 0) {
        i_errno = IERECVCOOKIE;
        return -1;
    }

    int i = 0;
    for (; i <= master_test->max_fd ; i++){
         if(i == s) continue;

        if ( master_test->test_map[i] && strcmp(master_test->current_cookie, master_test->test_map[i]->cookie) == 0) {
 
            isNewTest = 0; 
            break;
        }
    }
      
    int testCount = 10;
    if (isNewTest) {

        master_test->test_map[s] = iperf_new_test(); 
        master_test->test_map[s]->mster_test = master_test;
        iperf_test_defaults(master_test->test_map[s]);	/* sets defaults */
        iperf_init_test_with_args(master_test,master_test->test_map[s]);


        /* Server free, accept new client */
        strcpy(master_test->test_map[s]->cookie, master_test->current_cookie);
         master_test->test_map[s]->ctrl_sck = master_test->current_sck;
         master_test->currunt_conn_type = CONN_CTRL;
     
        FD_SET(master_test->test_map[s]->ctrl_sck, &master_test->read_set);
    
        if (master_test->test_map[s]->ctrl_sck > master_test->max_fd) master_test->max_fd = master_test->test_map[s]->ctrl_sck ;

        if (iperf_set_send_state(master_test->test_map[s], PARAM_EXCHANGE) != 0){
            return -1;
        }
  
        if (iperf_exchange_parameters(master_test->test_map[s]) < 0){
            return -1;
        }

        if (master_test->server_affinity != -1) 
            if (iperf_setaffinity(master_test, master_test->server_affinity) != 0){
                return -1;
            }
            if (master_test->test_map[s]->on_connect)
                master_test->test_map[s]->on_connect(master_test->test_map[s]);

    }else if (testCount < 20){
         //   master_test->skt_to_test[s]=master_test->skt_to_test[i];
            master_test->test_map[s] = master_test->test_map[i] ;
            master_test->currunt_conn_type = CONN_STREAM;

    } else {
	/*
	 * Don't try to read from the socket.  It could block an ongoing test. 
	 * Just send ACCESS_DENIED.
         * Also, if sending failed, don't return an error, as the request is not related
         * to the ongoing test, and returning an error will terminate the test.
	 */
        if (Nwrite(s, (char*) &rbuf, sizeof(rbuf), Ptcp) < 0) {
            if (master_test->debug)
                printf("failed to send ACCESS_DENIED to an unsolicited connection request during active test\n");
        } else {
            if (master_test->debug)
                printf("successfully sent ACCESS_DENIED to an unsolicited connection request during active test\n");
        }
        master_test->currunt_conn_type = CONN_UNKNOWN;
        close(s);
    }

    return 0;
}


/**************************************************************************/
int
iperf_handle_message_server(struct iperf_test *test)
{
    int rval;
    struct iperf_stream *sp;

    // XXX: Need to rethink how this behaves to fit API
    if ((rval = Nread(test->ctrl_sck, (char*) &test->state, sizeof(signed char), Ptcp)) <= 0) {
        if (rval == 0) {
	    iperf_err(test, "the client has unexpectedly closed the connection");
            i_errno = IECTRLCLOSE;
            test->state = IPERF_DONE;
            return 0;
        } else {
            i_errno = IERECVMESSAGE;
            return -1;
        }
    }

    switch(test->state) {
        case TEST_START:
            break;
        case TEST_END:
	    test->done = 1;
            cpu_util(test->cpu_util);
            test->stats_callback(test);
            SLIST_FOREACH(sp, &test->streams, streams) {
                FD_CLR(sp->socket, &test->mster_test->read_set);
                FD_CLR(sp->socket, &test->mster_test->write_set);
                close(sp->socket);
            }
            test->reporter_callback(test);

	    if (iperf_set_send_state(test, EXCHANGE_RESULTS) != 0)
                return -1;
            if (iperf_exchange_results(test) < 0)
                return -1;
        
	    if (iperf_set_send_state(test, DISPLAY_RESULTS) != 0)
                return -1;
            if (test->on_test_finish)
                test->on_test_finish(test);
            break;
        case IPERF_DONE:
            break;
        case CLIENT_TERMINATE:
            i_errno = IECLIENTTERM;

	    // Temporarily be in DISPLAY_RESULTS phase so we can get
	    // ending summary statistics.
	    signed char oldstate = test->state;
	    cpu_util(test->cpu_util);
	    test->state = DISPLAY_RESULTS;

	    test->reporter_callback(test);
	    test->state = oldstate;

            // XXX: Remove this line below!
	    iperf_err(test, "the client has terminated");
            SLIST_FOREACH(sp, &test->streams, streams) {
                FD_CLR(sp->socket, &test->mster_test->read_set);
                FD_CLR(sp->socket, &test->mster_test->write_set);
                close(sp->socket);
            }
            test->state = IPERF_DONE;
            break;
        default:
            i_errno = IEMESSAGE;
            return -1;
    }

    return 0;
}

static void
server_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{
    struct iperf_test *test = client_data.p;
    struct iperf_stream *sp;

    test->timer = NULL;
    if (test->done)
        return;
    test->done = 1;
    /* Free streams */
    while (!SLIST_EMPTY(&test->streams)) {
        sp = SLIST_FIRST(&test->streams);
        SLIST_REMOVE_HEAD(&test->streams, streams);
        close(sp->socket);
        iperf_free_stream(sp);
    }
    close(test->ctrl_sck);
}

static void
server_stats_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{
    struct iperf_test *test = client_data.p;

    if (test->done)
        return;
    if (test->stats_callback)
	test->stats_callback(test);
}

static void
server_reporter_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{
    struct iperf_test *test = client_data.p;

    if (test->done)
        return;
 
    if (test->reporter_callback){
	    test->reporter_callback(test);
    }
}

static int
create_server_timers(struct iperf_test * test)
{
    struct iperf_time now;
    TimerClientData cd;
    int max_rtt = 4; /* seconds */
    int state_transitions = 10; /* number of state transitions in iperf3 */
    int grace_period = max_rtt * state_transitions;

    if (iperf_time_now(&now) < 0) {
	i_errno = IEINITTEST;
	return -1;
    }
    cd.p = test;
    test->timer = test->stats_timer = test->reporter_timer = NULL;
    if (test->duration != 0 ) {
        test->done = 0;
        test->timer = tmr_create(&now, server_timer_proc, cd, (test->duration + test->omit + grace_period) * SEC_TO_US, 0);
        if (test->timer == NULL) {
            i_errno = IEINITTEST;
            return -1;
        }
    }

    test->stats_timer = test->reporter_timer = NULL;
    if (test->stats_interval != 0) {
        test->stats_timer = tmr_create(&now, server_stats_timer_proc, cd, test->stats_interval * SEC_TO_US, 1);
        if (test->stats_timer == NULL) {
            i_errno = IEINITTEST;
            return -1;
	}
    }
    if (test->reporter_interval != 0) {
        test->reporter_timer = tmr_create(&now, server_reporter_timer_proc, cd, test->reporter_interval * SEC_TO_US, 1);
        if (test->reporter_timer == NULL) {
            i_errno = IEINITTEST;
            return -1;
	}
    }
    return 0;
}

static void
server_omit_timer_proc(TimerClientData client_data, struct iperf_time *nowP)
{   
    struct iperf_test *test = client_data.p;

    test->omit_timer = NULL;
    test->omitting = 0;
    iperf_reset_stats(test);
    if (test->mster_test->verbose && !test->json_output && test->reporter_interval == 0)
	iperf_printf(test, "%s", report_omit_done);

    /* Reset the timers. */
    if (test->stats_timer != NULL)
	tmr_reset(nowP, test->stats_timer);
    if (test->reporter_timer != NULL)
	tmr_reset(nowP, test->reporter_timer);
}

static int
create_server_omit_timer(struct iperf_test * test)
{
    struct iperf_time now;
    TimerClientData cd; 

    if (test->omit == 0) {
	test->omit_timer = NULL;
	test->omitting = 0;
    } else {
	if (iperf_time_now(&now) < 0) {
	    i_errno = IEINITTEST;
	    return -1; 
	}
	test->omitting = 1;
	cd.p = test;
	test->omit_timer = tmr_create(&now, server_omit_timer_proc, cd, test->omit * SEC_TO_US, 0); 
	if (test->omit_timer == NULL) {
	    i_errno = IEINITTEST;
	    return -1;
	}
    }

    return 0;
}

static void
cleanup_test(struct iperf_test *test)
{

    struct iperf_stream *sp;

    /* Close open streams */
    SLIST_FOREACH(sp, &test->streams, streams) {
        FD_CLR(sp->socket, &test->mster_test->read_set);
        FD_CLR(sp->socket, &test->mster_test->write_set);
        close(sp->socket);
        
    }




    printf("Cleanin the cookie of  %d,  \n",test->ctrl_sck); 
    memset(test->cookie, 0, COOKIE_SIZE);

        /* Close open test sockets */
    if (test->ctrl_sck) {
	    close(test->ctrl_sck);
        test->ctrl_sck = -1;
    }
    // if (test->mster_test->listener) {
	//     close(test->mster_test->listener);
    // }
    if (test->prot_listener > -1) {     // May remain open if create socket failed
	    close(test->prot_listener);
        test->prot_listener = -1;
    }

    /* Cancel any remaining timers. */
    if (test->stats_timer != NULL) {
        tmr_cancel(test->stats_timer);
        test->stats_timer = NULL;
    }
    if (test->reporter_timer != NULL) {
        tmr_cancel(test->reporter_timer);
        test->reporter_timer = NULL;
    }
    if (test->omit_timer != NULL) {
        tmr_cancel(test->omit_timer);
        test->omit_timer = NULL;
    }
    if (test->congestion_used != NULL) {
        free(test->congestion_used);
    	test->congestion_used = NULL;
    }
    if (test->timer != NULL) {
        tmr_cancel(test->timer);
        test->timer = NULL;
    }
}

static void
cleanup_server(struct iperf_master_test *test)
{
    struct iperf_stream *sp;

      printf("Clean up tests too \n");         


    // /* Close open streams */
    // SLIST_FOREACH(sp, &test->streams, streams) {
	// FD_CLR(sp->socket, &test->mster_test->read_set);
	// FD_CLR(sp->socket, &test->mster_test->write_set);
	// close(sp->socket);
    // }

    /* Close open test sockets */
    if (test->current_sck) {
	close(test->current_sck);
    }
    if (test->listener) {
	close(test->listener);
    }
    if (test->prot_listener > -1) {     // May remain open if create socket failed
	close(test->prot_listener);
    }

    /* Cancel any remaining timers. */
    if (test->stats_timer != NULL) {
	tmr_cancel(test->stats_timer);
	test->stats_timer = NULL;
    }
    if (test->reporter_timer != NULL) {
	tmr_cancel(test->reporter_timer);
	test->reporter_timer = NULL;
    }
    if (test->omit_timer != NULL) {
	tmr_cancel(test->omit_timer);
	test->omit_timer = NULL;
    }
    if (test->congestion_used != NULL) {
        free(test->congestion_used);
	test->congestion_used = NULL;
    }
    if (test->timer != NULL) {
        tmr_cancel(test->timer);
        test->timer = NULL;
    }
}


int
iperf_run_server(struct iperf_master_test *master_test)
{
    int result, s;
 //   int send_streams_accepted, rec_streams_accepted;
//    int streams_to_send = 0, streams_to_rec = 0;
#if defined(HAVE_TCP_CONGESTION)
    int saved_errno;
#endif /* HAVE_TCP_CONGESTION */
    fd_set read_set, write_set;
    struct iperf_stream *sp;
    struct iperf_time now;
    struct iperf_time last_receive_time;
    struct iperf_time diff_time;
    struct timeval* timeout;
    struct timeval used_timeout;
    int flag;
    int64_t t_usecs;
    int64_t timeout_us;
    int64_t rcv_timeout_us;

    if (master_test->logfile)
        if (iperf_open_logfile(master_test) < 0)
            return -1;

    if (master_test->affinity != -1) 
	if (iperf_setaffinity(master_test, master_test->affinity) != 0)
	    return -2;

    if (master_test->json_output)
	if (iperf_json_start(master_test) < 0)
	    return -2;

    if (master_test->json_output) {
        cJSON_AddItemToObject(master_test->json_start, "version", cJSON_CreateString(version));
        cJSON_AddItemToObject(master_test->json_start, "system_info", cJSON_CreateString(get_system_info()));
    } else if (master_test->verbose) {
        iperf_printf_master(master_test, "%s\n", version);
        iperf_printf_master(master_test, "%s", "");
        iperf_printf_master(master_test, "%s\n", get_system_info());
	    iflush(master_test);
    }

    // Open socket and listen
    if (iperf_server_listen(master_test) < 0) {
        return -2;
    }


    iperf_time_now(&last_receive_time); // Initialize last time something was received
    master_test->state = IPERF_START;
    // send_streams_accepted = 0;
    // rec_streams_accepted = 0;
    rcv_timeout_us = (master_test->settings->rcv_timeout.secs * SEC_TO_US) + master_test->settings->rcv_timeout.usecs;


    while (1) {

        // Check if average transfer rate was exceeded (condition set in the callback routines)
        if (master_test->bitrate_limit_exceeded) {
            cleanup_server(master_test);
                i_errno = IETOTALRATE;
                return -1;	
        }

        memcpy(&read_set, &master_test->read_set, sizeof(fd_set));
        memcpy(&write_set, &master_test->write_set, sizeof(fd_set));

	    iperf_time_now(&now);
	    timeout = tmr_timeout(&now);

        // Ensure select() will timeout to allow handling error cases that require server restart
        if (master_test->state == IPERF_START) {       // In idle mode server may need to restart
            if (timeout == NULL && master_test->settings->idle_timeout > 0) {
                used_timeout.tv_sec = master_test->settings->idle_timeout;
                used_timeout.tv_usec = 0;
                timeout = &used_timeout;
            }
        } else if (master_test->mode != SENDER) {     // In non-reverse active mode server ensures data is received
            timeout_us = -1;
            if (timeout != NULL) {
                used_timeout.tv_sec = timeout->tv_sec;
                used_timeout.tv_usec = timeout->tv_usec;
                timeout_us = (timeout->tv_sec * SEC_TO_US) + timeout->tv_usec;
            }
            if (timeout_us < 0 || timeout_us > rcv_timeout_us) {
                used_timeout.tv_sec = master_test->settings->rcv_timeout.secs;
                used_timeout.tv_usec = master_test->settings->rcv_timeout.usecs;
            }
            timeout = &used_timeout;
        }

        result = select(master_test->max_fd + 1, &read_set, &write_set, NULL, timeout);
  
        if (result < 0 && errno != EINTR) {
            printf( "  cleanup_server    result,errno), %d, %d   \n",result,errno);
            cleanup_server(master_test);
            i_errno = IESELECT;
            return -1;
        } else if (result == 0) {
            // If nothing was received during the specified time (per state)
            // then probably something got stack either at the client, server or network,
            // and Test should be forced to end.
            iperf_time_now(&now);
            t_usecs = 0;
            if (iperf_time_diff(&now, &last_receive_time, &diff_time) == 0) {
                t_usecs = iperf_time_in_usecs(&diff_time);
                if (master_test->state == IPERF_START) {
                    if (master_test->settings->idle_timeout > 0 && t_usecs >= master_test->settings->idle_timeout * SEC_TO_US) {
                        master_test->server_forced_idle_restarts_count += 1;
                        if (master_test->debug)
                            printf("Server restart (#%d) in idle state as no connection request was received for %d sec\n",
                                master_test->server_forced_idle_restarts_count, master_test->settings->idle_timeout);
                                printf( "  cleanup_server    3  \n");
                        cleanup_server(master_test);
			if ( iperf_get_test_one_off(master_test) ) {
			  if (master_test->debug)
                            printf("No connection request was received for %d sec in one-off mode; exiting.\n",
				   master_test->settings->idle_timeout);
			  exit(0);
			}

                        return 2;
                    }
                }
                else if (master_test->mode != SENDER && t_usecs > rcv_timeout_us) {
                    master_test->server_forced_no_msg_restarts_count += 1;
                    i_errno = IENOMSG;
                    if (iperf_get_verbose(master_test))
                        iperf_err_master(master_test, "Server restart (#%d) during active test due to idle data for receiving data",
                                  master_test->server_forced_no_msg_restarts_count);
                    

                    cleanup_server(master_test);
                    return -1;
                }

            }
        }

	    if (result > 0) {
            iperf_time_now(&last_receive_time);
            if (FD_ISSET(master_test->listener, &read_set)) {
     
                    if (iperf_accept(master_test) < 0) {
			            cleanup_server(master_test);
                        return -1;
                    }

                    int current_sck = master_test->current_sck;

                    if(master_test->currunt_conn_type ==CONN_CTRL){
                        // Set streams number
                        if (master_test->test_map[current_sck]->mode == BIDIRECTIONAL) {
                            master_test->test_map[current_sck]->streams_to_send = master_test->test_map[current_sck]->num_streams;
                            master_test->test_map[current_sck]->streams_to_rec = master_test->test_map[current_sck]->num_streams;
                        } else if (master_test->test_map[master_test->current_sck]->mode == RECEIVER) {
                            master_test->test_map[current_sck]->streams_to_rec = master_test->test_map[current_sck]->num_streams;
                            master_test->test_map[current_sck]->streams_to_send = 0;
                        } else {
                            master_test->test_map[current_sck]->streams_to_send = master_test->test_map[current_sck]->num_streams;
                            master_test->test_map[current_sck]->streams_to_rec = 0;
                        }
                    }else if(master_test->currunt_conn_type ==CONN_STREAM){
            

                            if (!is_closed(current_sck)) {
                             
                                #if defined(HAVE_TCP_CONGESTION)
                                        if (master_test->test_map[current_sck]->protocol->id == Ptcp) {
                                        if (master_test->test_map[current_sck]->congestion) {
                                            if (setsockopt(s, IPPROTO_TCP, TCP_CONGESTION, master_test->test_map[current_sck]->congestion, strlen(master_test->test_map[current_sck]->congestion)) < 0) {
                                            /*
                                            * ENOENT means we tried to set the
                                            * congestion algorithm but the algorithm
                                            * specified doesn't exist.  This can happen
                                            * if the client and server have different
                                            * congestion algorithms available.  In this
                                            * case, print a warning, but otherwise
                                            * continue.
                                            */
                                            if (errno == ENOENT) {
                                                warning("TCP congestion control algorithm not supported");
                                            }
                                            else {
                                                saved_errno = errno;
                                                close(s);
                                                cleanup_server(master_test);
                                                errno = saved_errno;
                                                i_errno = IESETCONGESTION;
                                                return -1;
                                            }
                                            } 
                                        }
                                        {
                                            socklen_t len = TCP_CA_NAME_MAX;
                                            char ca[TCP_CA_NAME_MAX + 1];
                                                        int rc;
                                            rc = getsockopt(s, IPPROTO_TCP, TCP_CONGESTION, ca, &len);
                                                        if (rc < 0 && master_test->test_map[current_sck]->congestion) {
                                            saved_errno = errno;
                                            close(s);
                                            cleanup_server(master_test);
                                            errno = saved_errno;
                                            i_errno = IESETCONGESTION;
                                            return -1;
                                            }
                                                        /* 
                                                        * If not the first connection, discard prior
                                                        * congestion algorithm name so we don't leak
                                                        * duplicated strings.  We probably don't need
                                                        * the old string anyway.
                                                        */
                                                        if (master_test->test_map[current_sck]->congestion_used != NULL) {
                                                            free(master_test->test_map[current_sck]->congestion_used);
                                                        }
                                                        // Set actual used congestion alg, or set to unknown if could not get it
                                                        if (rc < 0)
                                                            master_test->test_map[current_sck]->congestion_used = strdup("unknown");
                                                        else
                                                            master_test->test_map[current_sck]->congestion_used = strdup(ca);
                                            if (master_test->test_map[current_sck]->debug) {
                                            printf("Congestion algorithm is %s\n", master_test->test_map[current_sck]->congestion_used);
                                            }
                                        }
                                        }
                                #endif /* HAVE_TCP_CONGESTION */



                    


                                if (master_test->test_map[current_sck]->rec_streams_accepted != master_test->test_map[current_sck]->streams_to_rec) {
                                    flag = 0;
                                    ++(master_test->test_map[current_sck]->rec_streams_accepted);
                                } else if (master_test->test_map[current_sck]->send_streams_accepted != master_test->test_map[current_sck]->streams_to_send) {
                                    flag = 1;
                                    ++(master_test->test_map[current_sck]->send_streams_accepted);
                                }


                                if (flag != -1) {

                                 
                                    sp = iperf_new_stream(master_test->test_map[current_sck], master_test->current_sck , flag);
                                    if (!sp) {
                                        cleanup_server(master_test);
                                        return -1;
                                    }

                                    if (sp->sender)
                                        FD_SET(current_sck, &master_test->write_set);
                                    else
                                        FD_SET(current_sck, &master_test->read_set);

                                    if (current_sck > master_test->max_fd) master_test->max_fd = current_sck;

                                    /*
                                    * If the protocol isn't UDP, or even if it is but
                                    * we're the receiver, set nonblocking sockets.
                                    * We need this to allow a server receiver to
                                    * maintain interactivity with the control channel.
                                    */
                                    if (master_test->test_map[current_sck]->protocol->id != Pudp ||
                                        !sp->sender) {
                                        setnonblocking(s, 1);
                                    }

                                    if (master_test->test_map[current_sck]->on_new_stream)
                                        master_test->test_map[current_sck]->on_new_stream(sp);

                                    flag = -1;
                                }
                            }
         
                        if (master_test->test_map[current_sck]->rec_streams_accepted == master_test->test_map[current_sck]->streams_to_rec && master_test->test_map[current_sck]->send_streams_accepted == master_test->test_map[current_sck]->streams_to_send) {

                            if (master_test->test_map[current_sck]->protocol->id != Ptcp) {
                                FD_CLR(master_test->test_map[current_sck]->prot_listener, &master_test->read_set);
                                close(master_test->test_map[current_sck]->prot_listener);
                            } else { 
                                if (master_test->test_map[current_sck]->no_delay || master_test->test_map[current_sck]->settings->mss || master_test->test_map[current_sck]->settings->socket_bufsize) {
                                    FD_CLR(master_test->listener, &master_test->read_set);
                                    close(master_test->listener);
                                    master_test->listener = 0;
                                            if ((s = netannounce(master_test->settings->domain, Ptcp, master_test->bind_address, master_test->bind_dev, master_test->server_port)) < 0) {
                                                
                                          
                                                cleanup_server(master_test);
                                                i_errno = IELISTEN;
                                                return -1;
                                            }
                                            master_test->listener = s;
                                            FD_SET(master_test->listener, &master_test->read_set);
                                    if (master_test->listener > master_test->max_fd) master_test->max_fd = master_test->listener;
                                }
                            }
                            master_test->test_map[current_sck]->prot_listener = -1;

                            /* Ensure that total requested data rate is not above limit */
                            iperf_size_t total_requested_rate = master_test->test_map[current_sck]->num_streams * master_test->test_map[current_sck]->settings->rate * (master_test->test_map[current_sck]->mode == BIDIRECTIONAL? 2 : 1);
                            if (master_test->test_map[current_sck]->settings->bitrate_limit > 0 && total_requested_rate > master_test->test_map[current_sck]->settings->bitrate_limit) {
                                        if (iperf_get_verbose(master_test))
                                            iperf_err_master(master_test, "Client total requested throughput rate of %" PRIu64 " bps exceeded %" PRIu64 " bps limit",
                                                    total_requested_rate, master_test->settings->bitrate_limit);


                                cleanup_server(master_test);
                                i_errno = IETOTALRATE;
                                return -1;
                            }

                            // Begin calculating CPU utilization
                            cpu_util(NULL);

                            if (iperf_set_send_state(master_test->test_map[current_sck], TEST_START) != 0) {
                                cleanup_test(master_test->test_map[current_sck]);
                                return -1;
                            }

                            if (iperf_init_test(master_test->test_map[current_sck]) < 0) {
                                cleanup_test(master_test->test_map[current_sck]);
                                return -1;
                            }
                            if (create_server_timers(master_test->test_map[current_sck]) < 0) {
                                cleanup_test(master_test->test_map[current_sck]);
                                return -1;
                            }
                            if (create_server_omit_timer(master_test->test_map[current_sck]) < 0) {
                                cleanup_test(master_test->test_map[current_sck]);
                                return -1;
                            }
                            if (master_test->test_map[current_sck]->mode != RECEIVER)
                            if (iperf_create_send_timers(master_test->test_map[current_sck]) < 0) {
                                cleanup_test(master_test->test_map[current_sck]);
                                return -1;
                            }

                            if (iperf_set_send_state(master_test->test_map[current_sck], TEST_RUNNING) != 0) {
                                cleanup_test(master_test->test_map[current_sck]);
                                return -1;
                            }


                        }

                    }

                    FD_CLR(master_test->listener, &read_set);

            }

            for(int i=0;i <= master_test->max_fd;i++){
                
                    if(master_test->test_map[i] && master_test->test_map[i]->ctrl_sck == i){
                         if (FD_ISSET(i, &read_set)) {
           
                            if (iperf_handle_message_server(master_test->test_map[i]) < 0) {
                                cleanup_test(master_test->test_map[i]);
                                        return -1;
                            }

                            iperf_reset_single_test(master_test->test_map[i]);
                            master_test->test_map[i] = NULL;
                            close(i);
                            FD_CLR(i, &master_test->read_set);  
                         }
                    }


                    if (master_test->test_map[i] && master_test->test_map[i]->state == TEST_RUNNING) {
                        if (master_test->test_map[i]->mode == BIDIRECTIONAL) {

                            if (iperf_recv(master_test->test_map[i], &read_set) < 0) {
                                cleanup_test(master_test->test_map[i]);
                                return -1;
                            }
                            if (iperf_send(master_test->test_map[i], &write_set) < 0) {
                                cleanup_test(master_test->test_map[i]);
                                return -1;
                            }
                        } else if (master_test->test_map[i]->mode == SENDER) {
                            // Reverse mode. Server sends.
                            if (iperf_send(master_test->test_map[i], &write_set) < 0) {
                                cleanup_test(master_test->test_map[i]);
                                return -1;
                            }
                        } else {
                            // Regular mode. Server receives.
                            if (iperf_recv(master_test->test_map[i], &read_set) < 0) {
                                cleanup_test(master_test->test_map[i]);
                                return -1;
                            }
                        }
                    }
            }
        }

        if (result == 0 ||
            (timeout != NULL && timeout->tv_sec == 0 && timeout->tv_usec == 0)) {
            /* Run the timers. */
            iperf_time_now(&now);
            tmr_run(&now);
        }
    }

    cleanup_server(master_test);

    if (master_test->json_output) {
	if (iperf_json_finish(master_test) < 0)
	    return -1;
    } 

    iflush(master_test);

    if (master_test->server_affinity != -1) 
	if (iperf_clearaffinity(master_test) != 0)
	    return -1;

    return 0;
}

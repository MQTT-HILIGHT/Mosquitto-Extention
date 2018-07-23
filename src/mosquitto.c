/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#define _DUMMYPTHREAD_H_ //스레드

#include <config.h>

#ifndef WIN32
/* For initgroups() */
#  define _BSD_SOURCE
#  include <unistd.h>
#  include <grp.h>
#  include <assert.h>
#endif

#ifndef WIN32
#include <pwd.h>
#else
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifndef WIN32
#  include <sys/time.h>
#endif

#include <pthread.h> //스레드

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#ifdef WITH_WRAP
#include <tcpd.h>
#endif
#ifdef WITH_WEBSOCKETS
#  include <libwebsockets.h>
#endif

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include "util_mosq.h"

struct mosquitto_db int_db;
struct mosquitto_db int_db2; //hilight db

typedef struct hilight_loop_param { // 스레드 파람
	int argc;
	char **argv;
}hilight_loop_param;

bool flag_reload = false;
#ifdef WITH_PERSISTENCE
bool flag_db_backup = false;
#endif
bool flag_tree_print = false;
int run;
#ifdef WITH_WRAP
#include <syslog.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_INFO;
#endif

void handle_sigint(int signal);
void handle_sigusr1(int signal);
void handle_sigusr2(int signal);

struct mosquitto_db *_mosquitto_get_db(void)
{
	return &int_db;
}

struct mosquitto_db *_mosquitto_get_db2(void)
{
	return &int_db2;
}


/*
hilight code
*/
int hilight_main(void *param);

/* mosquitto shouldn't run as root.
 * This function will attempt to change to an unprivileged user and group if
 * running as root. The user is given in config->user.
 * Returns 1 on failure (unknown user, setuid/setgid failure)
 * Returns 0 on success.
 * Note that setting config->user to "root" does not produce an error, but it
 * strongly discouraged.
 */
int drop_privileges(struct mqtt3_config *config, bool temporary)
{
#if !defined(__CYGWIN__) && !defined(WIN32)
	struct passwd *pwd;
	char err[256];
	int rc;

	if(geteuid() == 0){
		if(config->user && strcmp(config->user, "root")){
			pwd = getpwnam(config->user);
			if(!pwd){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid user '%s'.", config->user);
				return 1;
			}
			if(initgroups(config->user, pwd->pw_gid) == -1){
				strerror_r(errno, err, 256);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting groups whilst dropping privileges: %s.", err);
				return 1;
			}
			if(temporary){
				rc = setegid(pwd->pw_gid);
			}else{
				rc = setgid(pwd->pw_gid);
			}
			if(rc == -1){
				strerror_r(errno, err, 256);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting gid whilst dropping privileges: %s.", err);
				return 1;
			}
			if(temporary){
				rc = seteuid(pwd->pw_uid);
			}else{
				rc = setuid(pwd->pw_uid);
			}
			if(rc == -1){
				strerror_r(errno, err, 256);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting uid whilst dropping privileges: %s.", err);
				return 1;
			}
		}
		if(geteuid() == 0 || getegid() == 0){
			_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Mosquitto should not be run as root/administrator.");
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}

int restore_privileges(void)
{
#if !defined(__CYGWIN__) && !defined(WIN32)
	char err[256];
	int rc;

	if(getuid() == 0){
		rc = setegid(0);
		if(rc == -1){
			strerror_r(errno, err, 256);
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting gid whilst restoring privileges: %s.", err);
			return 1;
		}
		rc = seteuid(0);
		if(rc == -1){
			strerror_r(errno, err, 256);
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting uid whilst restoring privileges: %s.", err);
			return 1;
		}
	}
#endif
	return MOSQ_ERR_SUCCESS;
}

#ifdef SIGHUP
/* Signal handler for SIGHUP - flag a config reload. */
void handle_sighup(int signal)
{
	flag_reload = true;
}
#endif

/* Signal handler for SIGINT and SIGTERM - just stop gracefully. */
void handle_sigint(int signal)
{
	run = 0;
}

/* Signal handler for SIGUSR1 - backup the db. */
void handle_sigusr1(int signal)
{
#ifdef WITH_PERSISTENCE
	flag_db_backup = true;
#endif
}

void mosquitto__daemonise(void)
{
#ifndef WIN32
	char err[256];
	pid_t pid;

	pid = fork();
	if(pid < 0){
		strerror_r(errno, err, 256);
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error in fork: %s", err);
		exit(1);
	}
	if(pid > 0){
		exit(0);
	}
	if(setsid() < 0){
		strerror_r(errno, err, 256);
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error in setsid: %s", err);
		exit(1);
	}

	assert(freopen("/dev/null", "r", stdin));
	assert(freopen("/dev/null", "w", stdout));
	assert(freopen("/dev/null", "w", stderr));
#else
	_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Can't start in daemon mode in Windows.");
#endif
}

/* Signal handler for SIGUSR2 - vacuum the db. */
void handle_sigusr2(int signal)
{
	flag_tree_print = true;
}

int main(int argc, char *argv[])
{
	mosq_sock_t *listensock = NULL;
	int listensock_count = 0;
	int listensock_index = 0;

	struct mqtt3_config config;
#ifdef WITH_SYS_TREE
	char buf[1024];
#endif
	int i, j;
	FILE *pid;
	int listener_max;

	int rc;
	pthread_t thread_t;//스레드
	hilight_loop_param *loop_param;//스레드
#ifdef WIN32
	SYSTEMTIME st;
#else
	struct timeval tv;
#endif
	struct mosquitto *ctxt, *ctxt_tmp;

	//수정 스레드 시작
	hilight_init_queue(&hilight_urgency_queue);
	loop_param = (hilight_loop_param *)_mosquitto_malloc(sizeof(hilight_loop_param));
	loop_param->argc = argc;
	loop_param->argv = (char **)_mosquitto_malloc(sizeof(char *)*(loop_param->argc));

	for (i = 0; i < loop_param->argc; i++) {
		loop_param->argv[i] = (char *)_mosquitto_malloc(sizeof(char)*strlen(argv[i]) + 1);
		strcpy(loop_param->argv[i], argv[i]);
	}

	pthread_create(&thread_t, NULL, hilight_main, (void *)loop_param);  //스레드

#if defined(WIN32) || defined(__CYGWIN__)
	if(argc == 2){
		if(!strcmp(argv[1], "run")){
			service_run();
			return 0;
		}else if(!strcmp(argv[1], "install")){
			service_install();
			return 0;
		}else if(!strcmp(argv[1], "uninstall")){
			service_uninstall();
			return 0;
		}
	}
#endif


#ifdef WIN32
	GetSystemTime(&st);
	srand(st.wSecond + st.wMilliseconds);
#else
	gettimeofday(&tv, NULL);
	srand(tv.tv_sec + tv.tv_usec);
#endif

	memset(&int_db, 0, sizeof(struct mosquitto_db));

	_mosquitto_net_init();

	mqtt3_config_init(&config);
	config.config_id = 0; //수정수정수정
	rc = mqtt3_config_parse_args(&config, argc, argv);
	if(rc != MOSQ_ERR_SUCCESS) return rc;
	int_db.config = &config;

	if(config.daemon){
		mosquitto__daemonise();
	}

	if(config.daemon && config.pid_file){
		pid = _mosquitto_fopen(config.pid_file, "wt", false);
		if(pid){
			fprintf(pid, "%d", getpid());
			fclose(pid);
		}else{
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to write pid file.");
			return 1;
		}
	}

	rc = mqtt3_db_open(&config, &int_db);
	if(rc != MOSQ_ERR_SUCCESS){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Couldn't open database.");
		return rc;
	}

	/* Initialise logging only after initialising the database in case we're
	 * logging to topics */
	if(mqtt3_log_init(&config)){
		rc = 1;
		return rc;
	}
	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s (build date %s) starting", VERSION, TIMESTAMP);
	if(config.config_file){
		_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Config loaded from %s.", config.config_file);
	}else{
		_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Using default config.");
	}

	rc = mosquitto_security_module_init(&int_db);
	if(rc) return rc;
	rc = mosquitto_security_init(&int_db, false);
	if(rc) return rc;

#ifdef WITH_SYS_TREE
	if(config.sys_interval > 0){
		/* Set static $SYS messages */
		snprintf(buf, 1024, "mosquitto version %s", VERSION);
		mqtt3_db_messages_easy_queue(&int_db, NULL, "$SYS/broker/version", 2, strlen(buf), buf, 1);
		snprintf(buf, 1024, "%s", TIMESTAMP);
		mqtt3_db_messages_easy_queue(&int_db, NULL, "$SYS/broker/timestamp", 2, strlen(buf), buf, 1);
	}
#endif

	listener_max = -1;
	listensock_index = 0;
	for(i=0; i<config.listener_count; i++){
		if(config.listeners[i].protocol == mp_mqtt){
			if(mqtt3_socket_listen(&config.listeners[i])){
				mqtt3_db_close(&int_db);
				if(config.pid_file){
					remove(config.pid_file);
				}
				return 1;
			}
			listensock_count += config.listeners[i].sock_count;
			listensock = _mosquitto_realloc(listensock, sizeof(mosq_sock_t)*listensock_count);
			if(!listensock){
				mqtt3_db_close(&int_db);
				if(config.pid_file){
					remove(config.pid_file);
				}
				return 1;
			}
			for(j=0; j<config.listeners[i].sock_count; j++){
				if(config.listeners[i].socks[j] == INVALID_SOCKET){
					mqtt3_db_close(&int_db);
					if(config.pid_file){
						remove(config.pid_file);
					}
					return 1;
				}
				listensock[listensock_index] = config.listeners[i].socks[j];
				if(listensock[listensock_index] > listener_max){
					listener_max = listensock[listensock_index];
				}
				listensock_index++;
			}
		}else if(config.listeners[i].protocol == mp_websockets){
#ifdef WITH_WEBSOCKETS
			config.listeners[i].ws_context = mosq_websockets_init(&config.listeners[i], config.websockets_log_level);
			if(!config.listeners[i].ws_context){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to create websockets listener on port %d.", config.listeners[i].port);
				return 1;
			}
#endif
		}
	}

	rc = drop_privileges(&config, false);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);
#ifdef SIGHUP
	signal(SIGHUP, handle_sighup);
#endif
#ifndef WIN32
	signal(SIGUSR1, handle_sigusr1);
	signal(SIGUSR2, handle_sigusr2);
	signal(SIGPIPE, SIG_IGN);
#endif

#ifdef WITH_BRIDGE
	for(i=0; i<config.bridge_count; i++){
		if(mqtt3_bridge_new(&int_db, &(config.bridges[i]))){
			_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to connect to bridge %s.", 
					config.bridges[i].name);
		}
	}
#endif

	run = 1;
	rc = mosquitto_main_loop(&int_db, listensock, listensock_count, listener_max); //main loop 시작

	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s terminating", VERSION);
	mqtt3_log_close(&config);

#ifdef WITH_WEBSOCKETS
	for(i=0; i<int_db.config->listener_count; i++){
		if(int_db.config->listeners[i].ws_context){
			libwebsocket_context_destroy(int_db.config->listeners[i].ws_context);
		}
		if(int_db.config->listeners[i].ws_protocol){
			_mosquitto_free(int_db.config->listeners[i].ws_protocol);
		}
	}
#endif

	HASH_ITER(hh_id, int_db.contexts_by_id, ctxt, ctxt_tmp){
		mqtt3_context_send_will(&int_db, ctxt);
	}

#ifdef WITH_PERSISTENCE
	if(config.persistence){
		mqtt3_db_backup(&int_db, true);
	}
#endif

	HASH_ITER(hh_id, int_db.contexts_by_id, ctxt, ctxt_tmp){
#ifdef WITH_WEBSOCKETS
		if(!ctxt->wsi){
			mqtt3_context_cleanup(&int_db, ctxt, true);
		}
#else
		mqtt3_context_cleanup(&int_db, ctxt, true);
#endif
	}
	HASH_ITER(hh_sock, int_db.contexts_by_sock, ctxt, ctxt_tmp){
		mqtt3_context_cleanup(&int_db, ctxt, true);
	}
#ifdef WITH_BRIDGE
	for(i=0; i<int_db.bridge_count; i++){
		if(int_db.bridges[i]){
			mqtt3_context_cleanup(&int_db, int_db.bridges[i], true);
		}
	}
	if(int_db.bridges){
		_mosquitto_free(int_db.bridges);
	}
#endif
	mosquitto__free_disused_contexts(&int_db);

	mqtt3_db_close(&int_db);

	if(listensock){
		for(i=0; i<listensock_count; i++){
			if(listensock[i] != INVALID_SOCKET){
#ifndef WIN32
				close(listensock[i]);
#else
				closesocket(listensock[i]);
#endif
			}
		}
		_mosquitto_free(listensock);
	}
	mosquitto_security_module_cleanup(&int_db);

	if(config.pid_file){
		remove(config.pid_file);
	}

	mqtt3_config_cleanup(int_db.config);
	_mosquitto_net_cleanup();

	return rc;
}

#ifdef WIN32
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char **argv;
	int argc = 1;
	char *token;
	char *saveptr = NULL;
	int rc;

	argv = _mosquitto_malloc(sizeof(char *)*1);
	argv[0] = "mosquitto";
	token = strtok_r(lpCmdLine, " ", &saveptr);
	while(token){
		argc++;
		argv = _mosquitto_realloc(argv, sizeof(char *)*argc);
		if(!argv){
			fprintf(stderr, "Error: Out of memory.\n");
			return MOSQ_ERR_NOMEM;
		}
		argv[argc-1] = token;
		token = strtok_r(NULL, " ", &saveptr);
	}
	rc = main(argc, argv);
	_mosquitto_free(argv);
	return rc;
}
#endif


/*
hilight code
*/
int hilight_main(void *param) {

	mosq_sock_t *listensock = NULL;
	int listensock_count = 0;
	int listensock_index = 0;

	struct mqtt3_config config;
#ifdef WITH_SYS_TREE
	char buf[1024];
#endif
	int i, j;
	FILE *pid;
	int listener_max;

	int rc;
	hilight_loop_param *loop_param = param;//스레드
#ifdef WIN32
	SYSTEMTIME st;
#else
	struct timeval tv;
#endif
	struct mosquitto *ctxt, *ctxt_tmp;

	//스레드
	int cnt = 0;
	for (i = 0; i < loop_param->argc; i++) {
		if (strcmp(loop_param->argv[i], "-c") == 0) {
			cnt = 3;
			break;
		}		
	}
	if (cnt != 3) {
		loop_param->argv = (char **)_mosquitto_realloc(loop_param->argv, sizeof(char *)*(loop_param->argc + 2));
		for (i = loop_param->argc; i < loop_param->argc + 2; i++) {
			if (cnt == 0) {
				loop_param->argv[i] = (char *)_mosquitto_malloc(sizeof(char)*strlen("-p") + 1);
				strcpy(loop_param->argv[i], "-p");
			}
			else {
				loop_param->argv[i] = (char *)_mosquitto_malloc(sizeof(char)*strlen("1884") + 1);
				strcpy(loop_param->argv[i], "1884");
			}
			cnt++;
		}
		loop_param->argc += 2;
	}
	/*for (i = 0; i < loop_param->argc; i++) {
		printf("param 확인 : %s\n", loop_param->argv[i]);
	}*/


#if defined(WIN32) || defined(__CYGWIN__)
	if (loop_param->argc == 2) {
		if (!strcmp(loop_param->argv[1], "run")) {
			service_run();
			return 0;
		}
		else if (!strcmp(loop_param->argv[1], "install")) {
			service_install();
			return 0;
		}
		else if (!strcmp(loop_param->argv[1], "uninstall")) {
			service_uninstall();
			return 0;
		}
	}
#endif


#ifdef WIN32
	GetSystemTime(&st);
	srand(st.wSecond + st.wMilliseconds);
#else
	gettimeofday(&tv, NULL);
	srand(tv.tv_sec + tv.tv_usec);
#endif

	memset(&int_db2, 0, sizeof(struct mosquitto_db));

	_mosquitto_net_init();

	mqtt3_config_init(&config);
	config.config_id = 1; //수정수정수정
	rc = mqtt3_config_parse_args(&config, loop_param->argc, loop_param->argv);

	if (rc != MOSQ_ERR_SUCCESS) return rc;
	int_db2.config = &config;

	if (config.daemon) {
		mosquitto__daemonise();
	}

	if (config.daemon && config.pid_file) {
		pid = _mosquitto_fopen(config.pid_file, "wt", false);
		if (pid) {
			fprintf(pid, "%d", getpid());
			fclose(pid);
		}
		else {
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to write pid file.");
			return 1;
		}
	}

	rc = mqtt3_db_open(&config, &int_db2);
	if (rc != MOSQ_ERR_SUCCESS) {
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Couldn't open database.");
		return rc;
	}

	/* Initialise logging only after initialising the database in case we're
	* logging to topics */
	if (mqtt3_log_init(&config)) {
		rc = 1;
		return rc;
	}
	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s (build date %s) starting", VERSION, TIMESTAMP);
	if (config.config_file) {
		_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Config loaded from %s.", config.config_file);
	}
	else {
		_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Using default config.");
	}

	rc = mosquitto_security_module_init(&int_db2);
	if (rc) return rc;
	rc = mosquitto_security_init(&int_db2, false);
	if (rc) return rc;

#ifdef WITH_SYS_TREE
	if (config.sys_interval > 0) {
		/* Set static $SYS messages */
		snprintf(buf, 1024, "mosquitto version %s", VERSION);
		mqtt3_db_messages_easy_queue(&int_db2, NULL, "$SYS/broker/version", 2, strlen(buf), buf, 1);
		snprintf(buf, 1024, "%s", TIMESTAMP);
		mqtt3_db_messages_easy_queue(&int_db2, NULL, "$SYS/broker/timestamp", 2, strlen(buf), buf, 1);
	}
#endif

	listener_max = -1;
	listensock_index = 0;
	for (i = 0; i<config.listener_count; i++) {
		if (config.listeners[i].protocol == mp_mqtt) {
			if (mqtt3_socket_listen(&config.listeners[i])) {
				mqtt3_db_close(&int_db2);
				if (config.pid_file) {
					remove(config.pid_file);
				}
				return 1;
			}
			listensock_count += config.listeners[i].sock_count;
			listensock = _mosquitto_realloc(listensock, sizeof(mosq_sock_t)*listensock_count);
			if (!listensock) {
				mqtt3_db_close(&int_db2);
				if (config.pid_file) {
					remove(config.pid_file);
				}
				return 1;
			}
			for (j = 0; j<config.listeners[i].sock_count; j++) {
				if (config.listeners[i].socks[j] == INVALID_SOCKET) {
					mqtt3_db_close(&int_db2);
					if (config.pid_file) {
						remove(config.pid_file);
					}
					return 1;
				}
				listensock[listensock_index] = config.listeners[i].socks[j];
				if (listensock[listensock_index] > listener_max) {
					listener_max = listensock[listensock_index];
				}
				listensock_index++;
			}
		}
		else if (config.listeners[i].protocol == mp_websockets) {
#ifdef WITH_WEBSOCKETS
			config.listeners[i].ws_context = mosq_websockets_init(&config.listeners[i], config.websockets_log_level);
			if (!config.listeners[i].ws_context) {
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to create websockets listener on port %d.", config.listeners[i].port);
				return 1;
			}
#endif
		}
	}

	rc = drop_privileges(&config, false);
	if (rc != MOSQ_ERR_SUCCESS) return rc;

	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);
#ifdef SIGHUP
	signal(SIGHUP, handle_sighup);
#endif
#ifndef WIN32
	signal(SIGUSR1, handle_sigusr1);
	signal(SIGUSR2, handle_sigusr2);
	signal(SIGPIPE, SIG_IGN);
#endif

#ifdef WITH_BRIDGE
	for (i = 0; i<config.bridge_count; i++) {
		if (mqtt3_bridge_new(&int_db2, &(config.bridges[i]))) {
			_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Unable to connect to bridge %s.",
				config.bridges[i].name);
		}
	}
#endif

	run = 1;
	rc = hilight_main_loop(&int_db2, listensock, listensock_count, listener_max); //main loop 시작

	//스레드
	for (i = loop_param->argc; i < loop_param->argc; i++) {
		free(loop_param->argv[i]);
	}
	free(loop_param->argv);
	_mosquitto_free(loop_param);


	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s terminating", VERSION);
	mqtt3_log_close(&config);

#ifdef WITH_WEBSOCKETS
	for (i = 0; i<int_db2.config->listener_count; i++) {
		if (int_db2.config->listeners[i].ws_context) {
			libwebsocket_context_destroy(int_db2.config->listeners[i].ws_context);
		}
		if (int_db2.config->listeners[i].ws_protocol) {
			_mosquitto_free(int_db2.config->listeners[i].ws_protocol);
		}
	}
#endif

	HASH_ITER(hh_id, int_db2.contexts_by_id, ctxt, ctxt_tmp) {
		mqtt3_context_send_will(&int_db2, ctxt);
	}

#ifdef WITH_PERSISTENCE
	if (config.persistence) {
		mqtt3_db_backup(&int_db2, true);
	}
#endif

	HASH_ITER(hh_id, int_db2.contexts_by_id, ctxt, ctxt_tmp) {
#ifdef WITH_WEBSOCKETS
		if (!ctxt->wsi) {
			mqtt3_context_cleanup(&int_db2, ctxt, true);
		}
#else
		mqtt3_context_cleanup(&int_db2, ctxt, true);
#endif
	}
	HASH_ITER(hh_sock, int_db2.contexts_by_sock, ctxt, ctxt_tmp) {
		mqtt3_context_cleanup(&int_db2, ctxt, true);
	}
#ifdef WITH_BRIDGE
	for (i = 0; i<int_db2.bridge_count; i++) {
		if (int_db2.bridges[i]) {
			mqtt3_context_cleanup(&int_db2, int_db2.bridges[i], true);
		}
	}
	if (int_db2.bridges) {
		_mosquitto_free(int_db2.bridges);
	}
#endif
	mosquitto__free_disused_contexts(&int_db2);

	mqtt3_db_close(&int_db2);

	if (listensock) {
		for (i = 0; i<listensock_count; i++) {
			if (listensock[i] != INVALID_SOCKET) {
#ifndef WIN32
				close(listensock[i]);
#else
				closesocket(listensock[i]);
#endif
			}
		}
		_mosquitto_free(listensock);
	}
	mosquitto_security_module_cleanup(&int_db2);

	if (config.pid_file) {
		remove(config.pid_file);
	}

	mqtt3_config_cleanup(int_db2.config);
	_mosquitto_net_cleanup();

	return rc;
}


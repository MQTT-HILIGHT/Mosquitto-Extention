
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
#ifndef _UTIL_MOSQ_H_
#define _UTIL_MOSQ_H_

#include <stdio.h>

#include "tls_mosq.h"
#include "mosquitto.h"
#include "mosquitto_internal.h"

#ifdef WITH_BROKER
#  include "mosquitto_broker.h"
#endif

int _mosquitto_packet_alloc(struct _mosquitto_packet *packet);

#ifdef WITH_BROKER
void _mosquitto_check_keepalive(struct mosquitto_db *db, struct mosquitto *mosq);
#else
void _mosquitto_check_keepalive(struct mosquitto *mosq);
#endif

uint16_t _mosquitto_mid_generate(struct mosquitto *mosq);
FILE *_mosquitto_fopen(const char *path, const char *mode, bool restrict_read);

/*
* Highlight Code 수정
*/

void highlight_log_print(char *str);

typedef struct {
	struct mosquitto *head;  //subscribe head ptr
	char *payload;
	char *topic;
	int8_t retain;
	int16_t mid;
	int32_t payloadlen;
	int8_t dup;
	int8_t qos;
}element;

typedef struct Node //노드 정의
{
	element data;
	struct Node *next;
}Node;


typedef struct Queue //Queue 구조체 정의
{
	Node *front; //맨 앞(꺼낼 위치)
	Node *rear;  //맨 뒤(보관할 위치)
	int count;   //보관 개수
}Queue;

void highlight_init_queue(Queue *queue);
int highlight_is_empty(Queue *queue);
void highlight_enqueue(Queue *queue, element data);
void highlight_last_element_insert_subscribe(Queue *queue, struct mosquitto *context);
element highlight_dequeue(Queue *queue);

//sub list
void highlight_insert_node(struct mosquitto **phead, struct mosquitto *p, struct mosquitto *new_node);
void highlight_remove_node(struct mosquitto **phead, struct mosquitto *p, struct mosquitto *removed);
void highlight_display(struct mosquitto *head);
struct moquitto *highlight_find(struct mosquitto *head, struct mosquitto val);
struct moquitto *highlight_before_find(struct mosquitto *head, struct mosquitto val);

Queue highlight_urgency_queue;
Queue highlight_normal_queue;
int my_control_count; //control

#ifdef REAL_WITH_TLS_PSK
int _mosquitto_hex2bin(const char *hex, unsigned char *bin, int bin_max_len);
#endif

#endif

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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <config.h>

#include <mosquitto_broker.h>
#include <mqtt3_protocol.h>
#include <memory_mosq.h>
#include <read_handle.h>
#include <send_mosq.h>
#include <util_mosq.h>

#ifdef WITH_SYS_TREE
extern uint64_t g_pub_bytes_received;
#endif

int mqtt3_packet_handle(struct mosquitto_db *db, struct mosquitto *context) //broker packet handle control
{
	if(!context) return MOSQ_ERR_INVAL;

	switch((context->in_packet.command)&0xF0){
		case PINGREQ:
			return _mosquitto_handle_pingreq(context);
		case PINGRESP:
			return _mosquitto_handle_pingresp(context);
		case PUBACK:
			return _mosquitto_handle_pubackcomp(db, context, "PUBACK");
		case PUBCOMP:
			return _mosquitto_handle_pubackcomp(db, context, "PUBCOMP");
		case PUBLISH:
			return mqtt3_handle_publish(db, context);
		case PUBREC:
			return _mosquitto_handle_pubrec(context);
		case PUBREL:
			return _mosquitto_handle_pubrel(db, context);
		case CONNECT:
			//printf("connect\n"); //이미 연결된 클라이언트를 init? 해주는 부분 만약 연결이 애매하다면 여기서 계속 connack을 보냄
			return mqtt3_handle_connect(db, context); 
		case DISCONNECT:
			//printf("disconnect\n");
			return mqtt3_handle_disconnect(db, context);
		case SUBSCRIBE:
			//printf("subscribe\n");
			return mqtt3_handle_subscribe(db, context);
		case UNSUBSCRIBE:
			//printf("unsubscribe\n");
			return mqtt3_handle_unsubscribe(db, context);
#ifdef WITH_BRIDGE
		case CONNACK:
			//printf("connack\n");
			return mqtt3_handle_connack(db, context);
		case SUBACK:
			return _mosquitto_handle_suback(context);
		case UNSUBACK:
			return _mosquitto_handle_unsuback(context);
#endif
		default:
			/* If we don't recognise the command, return an error straight away. */
			return MOSQ_ERR_PROTOCOL;
	}
}

int mqtt3_handle_publish(struct mosquitto_db *db, struct mosquitto *context)
{
	char *topic;
	void *payload = NULL;
	uint32_t payloadlen;
	uint8_t dup, qos, retain;
	uint16_t mid = 0;
	int rc = 0;
	uint8_t header = context->in_packet.command;
	int res = 0;
	struct mosquitto_msg_store *stored = NULL;
	int len;
	char *topic_mount;
#ifdef WITH_BRIDGE
	char *topic_temp;
	int i;
	struct _mqtt3_bridge_topic *cur_topic;
	bool match;
#endif

	dup = (header & 0x08)>>3;
	qos = (header & 0x06)>>1;
	retain = (header & 0x01);

	if(_mosquitto_read_string(&context->in_packet, &topic)) return 1;
	if(STREMPTY(topic)){
		/* Invalid publish topic, disconnect client. */
		_mosquitto_free(topic);
		return 1;
	}

#ifdef WITH_BRIDGE
	if(context->bridge && context->bridge->topics && context->bridge->topic_remapping){
		for(i=0; i<context->bridge->topic_count; i++){
			cur_topic = &context->bridge->topics[i];
			if((cur_topic->direction == bd_both || cur_topic->direction == bd_in) 
					&& (cur_topic->remote_prefix || cur_topic->local_prefix)){

				/* Topic mapping required on this topic if the message matches */

				rc = mosquitto_topic_matches_sub(cur_topic->remote_topic, topic, &match);
				if(rc){
					_mosquitto_free(topic);
					return rc;
				}
				if(match){
					if(cur_topic->remote_prefix){
						/* This prefix needs removing. */
						if(!strncmp(cur_topic->remote_prefix, topic, strlen(cur_topic->remote_prefix))){
							topic_temp = _mosquitto_strdup(topic+strlen(cur_topic->remote_prefix));
							if(!topic_temp){
								_mosquitto_free(topic);
								return MOSQ_ERR_NOMEM;
							}
							_mosquitto_free(topic);
							topic = topic_temp;
						}
					}

					if(cur_topic->local_prefix){
						/* This prefix needs adding. */
						len = strlen(topic) + strlen(cur_topic->local_prefix)+1;
						topic_temp = _mosquitto_malloc(len+1);
						if(!topic_temp){
							_mosquitto_free(topic);
							return MOSQ_ERR_NOMEM;
						}
						snprintf(topic_temp, len, "%s%s", cur_topic->local_prefix, topic);
						topic_temp[len] = '\0';

						_mosquitto_free(topic);
						topic = topic_temp;
					}
					break;
				}
			}
		}
	}
#endif
	if(mosquitto_pub_topic_check(topic) != MOSQ_ERR_SUCCESS){
		/* Invalid publish topic, just swallow it. */
		_mosquitto_free(topic);
		return 1;
	}

	if(qos > 0){
		if(_mosquitto_read_uint16(&context->in_packet, &mid)){
			_mosquitto_free(topic);
			return 1;
		}
	}

	payloadlen = context->in_packet.remaining_length - context->in_packet.pos;
#ifdef WITH_SYS_TREE
	g_pub_bytes_received += payloadlen;
#endif
	if(context->listener && context->listener->mount_point){
		len = strlen(context->listener->mount_point) + strlen(topic) + 1;
		topic_mount = _mosquitto_malloc(len+1);
		if(!topic_mount){
			_mosquitto_free(topic);
			return MOSQ_ERR_NOMEM;
		}
		snprintf(topic_mount, len, "%s%s", context->listener->mount_point, topic);
		topic_mount[len] = '\0';

		_mosquitto_free(topic);
		topic = topic_mount;
	}

	if(payloadlen){
		if(db->config->message_size_limit && payloadlen > db->config->message_size_limit){
			_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Dropped too large PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);
			goto process_bad_message;
		}
		payload = _mosquitto_calloc(payloadlen+1, 1);
		if(!payload){
			_mosquitto_free(topic);
			return 1;
		}
		if(_mosquitto_read_bytes(&context->in_packet, payload, payloadlen)){
			_mosquitto_free(topic);
			_mosquitto_free(payload);
			return 1;
		}
	}

	/* Check for topic access */
	rc = mosquitto_acl_check(db, context, topic, MOSQ_ACL_WRITE);
	if(rc == MOSQ_ERR_ACL_DENIED){
		_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);
		goto process_bad_message;
	}else if(rc != MOSQ_ERR_SUCCESS){
		_mosquitto_free(topic);
		if(payload) _mosquitto_free(payload);
		return rc;
	}

	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);


	if (qos == 3) {		

		//enqueue 수정  @@
		element data;

		data.head = NULL;  //head 포인터 초기화
		
		data.payload = _mosquitto_malloc(sizeof(char)*payloadlen + 1);
		data.topic = _mosquitto_malloc(sizeof(char)*strlen(topic) + 1);
		strcpy(data.payload, payload);
		strcpy(data.topic, topic);

		data.dup = dup;
		data.mid = mid;
		data.qos = qos;
		data.retain = retain;
		data.payloadlen = payloadlen;

		hilight_enqueue(&hilight_urgency_queue, data); //urgency queue 에 넣음
	}


	/*else { //normal queue
		hilight_enqueue(&hilight_normal_queue, data);
	}*/

	if(qos > 0 && qos != 3){
		mqtt3_db_message_store_find(context, mid, &stored);
	}
	if(!stored){
		dup = 0;
		if(mqtt3_db_message_store(db, context->id, mid, topic, qos, payloadlen, payload, retain, &stored, 0)){
			_mosquitto_free(topic);
			if(payload) _mosquitto_free(payload);
			return 1;
		}
	}else{
		dup = 1;
	}
	//qos control
	switch(qos){
		case 0:
		case 3:
			if(mqtt3_db_messages_queue(db, context->id, topic, qos, retain, &stored)) rc = 1;
			
			break;
		case 1:
			if(mqtt3_db_messages_queue(db, context->id, topic, qos, retain, &stored)) rc = 1;
			if(_mosquitto_send_puback(context, mid)) rc = 1;
			break;
		case 2:
			if(!dup){
				res = mqtt3_db_message_insert(db, context, mid, mosq_md_in, qos, retain, stored);
			}else{
				res = 0;
			}
			/* mqtt3_db_message_insert() returns 2 to indicate dropped message
			 * due to queue. This isn't an error so don't disconnect them. */
			if(!res){
				if(_mosquitto_send_pubrec(context, mid)) rc = 1;
			}else if(res == 1){
				rc = 1;
			}
			break;
	}

	_mosquitto_free(topic);
	if(payload) _mosquitto_free(payload);

	return rc;
process_bad_message:
	_mosquitto_free(topic);
	if(payload) _mosquitto_free(payload);
	//qos control
	switch(qos){
		case 0:
		case 3:
			return MOSQ_ERR_SUCCESS;
		case 1:
			return _mosquitto_send_puback(context, mid);
		case 2:
			mqtt3_db_message_store_find(context, mid, &stored);
			if(!stored){
				if(mqtt3_db_message_store(db, context->id, mid, NULL, qos, 0, NULL, false, &stored, 0)){
					return 1;
				}
				res = mqtt3_db_message_insert(db, context, mid, mosq_md_in, qos, false, stored);
			}else{
				res = 0;
			}
			if(!res){
				res = _mosquitto_send_pubrec(context, mid);
			}
			return res;
	}
	return 1;
}


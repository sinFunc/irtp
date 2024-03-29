/*
 * Copyright (c) 2010-2022 Belledonne Communications SARL.
 *
 * This file is part of oRTP 
 * (see https://gitlab.linphone.org/BC/public/ortp).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "ortp-config.h"
#endif

#include <ortp/rtpsession.h>
#include "utils.h"


void rtp_signal_table_init(RtpSignalTable *table,RtpSession *session, const char *signal_name)
{
	memset(table,0,sizeof(RtpSignalTable));
	table->session=session;
	table->signal_name=signal_name;
	session->signal_tables=o_list_append(session->signal_tables,(void*)table);
}

int rtp_signal_table_add(RtpSignalTable *table,RtpCallback cb, void *user_data)
{
	int i;

	for (i=0;i<RTP_CALLBACK_TABLE_MAX_ENTRIES;i++){
		if (table->callback[i]==NULL){
			table->callback[i]=cb;
			table->user_data[i]=user_data;
			table->count++;
			return 0;
		}
	}
	return -1;
}


void rtp_signal_table_emit(RtpSignalTable *table)
{
	int i,c;

	for (i=0,c=0;c<table->count;i++){
		if (table->callback[i]!=NULL){
			c++;	/*I like it*/
			table->callback[i](table->session,table->user_data[i],0,0);
		}
	}
}

void rtp_signal_table_emit2(RtpSignalTable *table, void *arg)
{
	int i,c;

	for (i=0,c=0;c<table->count;i++){
		if (table->callback[i]!=NULL){
			c++;	/*I like it*/
			table->callback[i](table->session,arg,table->user_data[i],0);
		}
	}
}

void rtp_signal_table_emit3(RtpSignalTable *table, void *arg1, void *arg2)
{
	int i,c;

	for (i=0,c=0;c<table->count;i++){
		if (table->callback[i]!=NULL){
			c++;	/*I like it*/
			table->callback[i](table->session,arg1,arg2,table->user_data[i]);
		}
	}
}

int rtp_signal_table_remove_by_callback(RtpSignalTable *table,RtpCallback cb)
{
	int i;

	for (i=0;i<RTP_CALLBACK_TABLE_MAX_ENTRIES;i++){
		if (table->callback[i]==cb){
			table->callback[i]=NULL;
			table->user_data[i]=0;
			table->count--;
			return 0;
		}
	}
	return -1;
}

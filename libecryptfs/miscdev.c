/**
 * Userspace side of procfs communications with eCryptfs kernel
 * module.
 *
 * Copyright (C) 2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#ifndef S_SPLINT_S
#include <stdio.h>
#include <syslog.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../include/ecryptfs.h"

int ecryptfs_send_miscdev(struct ecryptfs_miscdev_ctx *miscdev_ctx,
			  struct ecryptfs_message *msg, uint8_t msg_type,
			  uint16_t msg_flags, uint32_t msg_seq)
{
	uint32_t miscdev_msg_data_size;
	size_t packet_len_size;
	size_t packet_len;
	uint32_t msg_seq_be32;
	uint32_t i;
	ssize_t written;
	char packet_len_str[3];
	char *miscdev_msg_data;
	int rc = 0;

	/* miscdevfs packet format:
	 *  Octet 0: Type
	 *  Octets 1-4: network byte order msg_ctx->counter
	 *  Octets 5-N0: Size of struct ecryptfs_message to follow
	 *  Octets N0-N1: struct ecryptfs_message (including data)
	 *
	 *  Octets 5-N1 not written if the packet type does not
	 *  include a message */
	if (msg) {
		packet_len = (sizeof(*msg) + msg->data_len);
		rc = ecryptfs_write_packet_length(packet_len_str, packet_len,
						  &packet_len_size);
		if (rc)
			goto out;
	} else {
		packet_len_size = 0;
		packet_len = 0;
	}
	miscdev_msg_data_size = (1 + 4 + packet_len_size + packet_len);
	miscdev_msg_data = malloc(miscdev_msg_data_size);
	if (!miscdev_msg_data) {
		rc = -ENOMEM;
		goto out;
	}
	msg_seq_be32 = htonl(msg_seq);
	i = 0;
	miscdev_msg_data[i++] = msg_type;
	memcpy(&miscdev_msg_data[i], (void *)&msg_seq_be32, 4);
	i += 4;
	if (msg) {
		memcpy(&miscdev_msg_data[i], packet_len_str, packet_len_size);
		i += packet_len_size;
		memcpy(&miscdev_msg_data[i], (void *)msg, packet_len);
	}
	written = write(miscdev_ctx->miscdev_fd, miscdev_msg_data,
			miscdev_msg_data_size);
	if (written == -1) {
		rc = -EIO;
		syslog(LOG_ERR, "Failed to send eCryptfs miscdev message; "
		       "errno msg = [%m]\n");
	}
	free(miscdev_msg_data);
out:
	return rc;
}

/**
 * ecryptfs_recv_miscdev
 * @msg: Allocated in this function; callee must deallocate
 */
int ecryptfs_recv_miscdev(struct ecryptfs_miscdev_ctx *miscdev_ctx,
			  struct ecryptfs_message **msg, uint32_t *msg_seq,
			  uint8_t *msg_type)
{
	ssize_t read_bytes;
	uint32_t miscdev_msg_data_size;
	size_t packet_len_size;
	size_t packet_len;
	uint32_t msg_seq_be32;
	uint32_t i;
	char *miscdev_msg_data;
	int rc = 0;

	miscdev_msg_data = malloc(ECRYPTFS_MSG_MAX_SIZE);
	if (!miscdev_msg_data) {
		rc = -ENOMEM;
		goto out;
	}
	read_bytes = read(miscdev_ctx->miscdev_fd, miscdev_msg_data,
			  ECRYPTFS_MSG_MAX_SIZE);
	if (read_bytes == -1) {
		rc = -EIO;
	syslog(LOG_ERR, "%s: Error attempting to read message from "
	       "miscdev handle; errno msg = [%m]\n", __FUNCTION__);
		goto out;
	}
	if (read_bytes < (1 + 4)) {
		rc = -EINVAL;
		syslog(LOG_ERR, "%s: Received invalid packet from kernel; "
		       "read_bytes = [%zu]; minimum possible packet site is "
		       "[%d]\n", __FUNCTION__, read_bytes,
		       (1 + 4));
		goto out;
	}
	i = 0;
	(*msg_type) = miscdev_msg_data[i++];
	memcpy((void *)&msg_seq_be32, &miscdev_msg_data[i], 4);
	i += 4;
	(*msg_seq) = ntohl(msg_seq_be32);
	if ((*msg_type) == ECRYPTFS_MSG_REQUEST) {
		rc = ecryptfs_parse_packet_length((unsigned char *)
						    &miscdev_msg_data[i],
						  &packet_len,
						  &packet_len_size);
		if (rc)
			goto out;
		i += packet_len_size;
	} else {
		packet_len_size = 0;
		packet_len = 0;
	}
	miscdev_msg_data_size = (1 + 4 + packet_len_size + packet_len);
	if (miscdev_msg_data_size != read_bytes) {
		rc = -EINVAL;
		syslog(LOG_ERR, "%s: Invalid packet. (1 + 4 + "
		       "packet_len_size=[%zu] + packet_len=[%zu])=[%zu] != "
		       "read_bytes=[%zu]\n", __FUNCTION__, packet_len_size,
		       packet_len, (1 + 4 + packet_len_size + packet_len),
		       read_bytes);
		goto out;
	}
	(*msg) = malloc(packet_len);
	if (!(*msg)) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy((void *)(*msg), (void *)&miscdev_msg_data[i], packet_len);
out:
	free(miscdev_msg_data);
	return rc;
}

int ecryptfs_init_miscdev(struct ecryptfs_miscdev_ctx *miscdev_ctx)
{
	int rc = 0;

	miscdev_ctx->miscdev_fd = open(ECRYPTFS_DEFAULT_MISCDEV_FULLPATH_0,
				       O_RDWR);
	if (miscdev_ctx->miscdev_fd == -1) {
		syslog(LOG_ERR, "%s: Error whilst attempting to open "
		       "[%s]; errno msg = [%m]\n", __FUNCTION__,
		       ECRYPTFS_DEFAULT_MISCDEV_FULLPATH_0);
	} else
		goto out;
	miscdev_ctx->miscdev_fd = open(ECRYPTFS_DEFAULT_MISCDEV_FULLPATH_1,
				       O_RDWR);
	if (miscdev_ctx->miscdev_fd == -1) {
		syslog(LOG_ERR, "%s: Error whilst attempting to open "
		       "[%s]; errno msg = [%m]\n", __FUNCTION__,
		       ECRYPTFS_DEFAULT_MISCDEV_FULLPATH_1);
		rc = -EIO;
	}
out:
	return rc;
}

void ecryptfs_release_miscdev(struct ecryptfs_miscdev_ctx *miscdev_ctx)
{
	close(miscdev_ctx->miscdev_fd);
}

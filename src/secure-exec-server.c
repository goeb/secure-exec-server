/*
 * Copyright (C) 2025 Frederic Hoerni
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <glib-unix.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "ses_crypto.h"
#include "ses_utils.h"

int usage()
{
    g_print("usage: ses TCP-PORT PEM-CERTIFICATE\n");
	return 1;
}

typedef struct {
	GMainLoop *mainloop;
    EVP_PKEY *public_key;
} general_context_t;

typedef struct {
    general_context_t *general_context;
	int client_identifier;
	guint8 *bytes_received;
	size_t bytes_received_len;
} connection_context_t;

/* Extend the buffer of received bytes and store the new bytes
 */
static void store(connection_context_t *ctx, guint8 *data, size_t len)
{
	// on first call, ctx->bytes_received is NULL, and g_realloc allocates
	ctx->bytes_received = g_realloc(ctx->bytes_received, ctx->bytes_received_len + len);
	memcpy(ctx->bytes_received + ctx->bytes_received_len, data, len);
	ctx->bytes_received_len += len;
}

/* Callback in charge of receiving bytes on the socket
 * @param fd          file descriptor of the socket
 * @param condition
 * @param user_data   connection context
 *
 * When bytes are received they are stored in a dedicated buffer.
 * When the connection is closed, if "shutdown\n" has been received
 * then it triggers the shutdown of the server.
 */
gboolean receive_data(gint fd, GIOCondition condition, gpointer user_data)
{
	connection_context_t *ctx = (connection_context_t*)user_data;
	int client_id = ctx->client_identifier;
	if (condition & G_IO_IN) {
		guint8 buffer[10];
		ssize_t n;
		n = read(fd, buffer, sizeof(buffer)-1);
		if (n == 0) {
			info("%d: connection closed by peer", client_id);
			goto close_fd; 
		} else if (n < 1) {
			info("%d: read error: %d", client_id, g_strerror(errno));
			goto close_fd; 
		} else if (n > 0) {
			buffer[n] = 0;
			info("%d: recv: %s", client_id, buffer); // assume printable characters only
			store(ctx, buffer, n);
		}
	}
	if (condition & G_IO_HUP) {
		info("%d: HUP", client_id);
		goto close_fd;
	}
	if (!(condition & G_IO_HUP) && !(condition & G_IO_IN)) {
		info("%d: unexpected condition 0x%x)", client_id, condition);
		goto close_fd;
	}

	return G_SOURCE_CONTINUE; // continue listening on this fd
close_fd:
    close(fd);
	if (0 == strncmp((char*)ctx->bytes_received, "shutdown\n", 9)) {
		info("%d: shutdown requested", client_id);
        g_main_loop_quit(ctx->general_context->mainloop);
		// not very clean shutdown as resources used by other connections
		// are not properly freed.
    } else {
        GError *error = NULL;
        int err = authenticate_script(ctx->bytes_received, ctx->bytes_received_len, ctx->general_context->public_key, &error);
        if (err) {
            info("%d: authentication FAILED: %s", client_id, error->message);
            g_error_free(error);
        } else {
            info("%d: authentication OK", client_id);
            // start the script
        }
    }
	g_free(ctx->bytes_received);
	g_free(ctx);
	return G_SOURCE_REMOVE; // stop monitoring this fd
}


/* Callback in charge of accepting a new incoming connection
 * @param fd          file descriptor of the listening socket
 * @param condition   not used (should always be G_IO_IN)
 * @param user_data   general context
 */
gboolean accept_incoming_connection(gint fd, GIOCondition condition, gpointer user_data)
{
	static int next_client_id = 0;
    general_context_t *general_context = (general_context_t*)user_data;

	int client_fd = accept(fd, NULL, NULL);
	if (client_fd < 0) {
		info("accept error: %s", g_strerror(errno));
		return G_SOURCE_CONTINUE; // continue listening
	}
	
	// allocate a client id for this connection
	connection_context_t *ctx = g_new0(connection_context_t, 1);
    ctx->general_context = general_context;
	ctx->client_identifier = next_client_id;
	next_client_id++;

	info("new client connected: %d", ctx->client_identifier);

	g_unix_fd_add(client_fd, G_IO_IN|G_IO_PRI|G_IO_ERR|G_IO_HUP, receive_data, (gpointer)ctx);

	return G_SOURCE_CONTINUE; // continue listening
}

/* Create a listening socket
 */
int create_listening_socket(uint16_t port)
{
	int err;
	const int max_queue = 5;

	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		info("failed to create socket: %s", g_strerror(errno));
		return -1;
	}

	int sockflag = 1;
	err = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &sockflag, sizeof(sockflag));
	if (err) {
		info("setsockopt error: %s", g_strerror(errno));
	}

	// Configure the server address
	struct sockaddr_in sockin;
	sockin.sin_family = AF_INET;
	sockin.sin_port = htons(port);
	sockin.sin_addr.s_addr = INADDR_ANY;

	err = bind(listen_fd, (struct sockaddr *)&sockin, sizeof(sockin));
	if (err) {
		info("bind error: %s", g_strerror(errno));
		close(listen_fd);
		return -1;
	}

	err = listen(listen_fd, max_queue);
	if (err) {
		info("listen error: %s", g_strerror(errno));
		close(listen_fd);
		return -1;
	}
	return listen_fd;
}

int main(int argc, char **argv)
{
    if (argc != 3) return usage();

    uint16_t port = strtoul(argv[1], NULL, 10); // errors not handled
    EVP_PKEY *pubkey = load_public_key(argv[2]);
    if (!pubkey) return 1;

	int listen_fd = create_listening_socket(port);
	if (listen_fd < 0) return 1;

	info("Server listening on TCP port %u", port);

	general_context_t ctx;
	ctx.mainloop = g_main_loop_new(NULL, FALSE);
    ctx.public_key = pubkey;

	g_unix_fd_add(listen_fd, G_IO_IN, accept_incoming_connection, (gpointer)&ctx);

	g_main_loop_run(ctx.mainloop);

	g_main_loop_unref(ctx.mainloop);
	close(listen_fd);

	info("exiting");
	return 0;
}

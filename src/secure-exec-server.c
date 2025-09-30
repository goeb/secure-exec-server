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
	g_print("usage: ses TCP-PORT CERTIFICATE ...\n"
	        "\n"
	        "Start a TCP server where clients can submit their scripts, that get\n"
	           "authenticated and executed.\n"
	        "\n"
	        "Arguments:\n"
	        "  CERTIFICATE  X509 certificate whose public key is used for authentication.\n"
	        "               It must be in PEM encoding.\n"
	        "               It must carry the x509v3 extension KeyUsage 'digitalSignature'.\n"
	        "               If several certificates are specified, the authentication\n"
	        "               will succeed if at least 1 certificate verifies the signature.\n"
	        "  TCP-PORT     Listening port\n"
	        );

	return 1;
}

typedef struct {
	GMainLoop *mainloop;
	GArray *public_keys; // null-terminated list of public keys
} general_context_t;

typedef struct {
	general_context_t *general_context;
	int client_identifier;
	uint8_t *bytes_received;
	size_t bytes_received_len;
	uint8_t *script_ptr; // pointer inside the allocated buffer pointed by bytes_received
	size_t script_len;
} connection_context_t;

/* Extend the buffer of received bytes and store the new bytes
 */
static void store(connection_context_t *ctx, uint8_t *data, size_t len)
{
	// on first call, ctx->bytes_received is NULL, and g_realloc allocates
	ctx->bytes_received = g_realloc(ctx->bytes_received, ctx->bytes_received_len + len);
	memcpy(ctx->bytes_received + ctx->bytes_received_len, data, len);
	ctx->bytes_received_len += len;
}

gboolean feed_stdin(gint fd, GIOCondition condition, gpointer user_data)
{
	connection_context_t *ctx = (connection_context_t*)user_data;
	DEBUG("%d: feed_stdin: condition=0x%x", ctx->client_identifier, condition);
	if (condition & G_IO_OUT) {
		ssize_t n = write(fd, ctx->script_ptr, ctx->script_len);
		DEBUG("%d: feed_stdin: write: n=%ld", ctx->client_identifier, n);
		if (n < 0 && errno == EPIPE) {
			INFO("%d: feed_stdin: got EPIPE, termination of child", ctx->client_identifier);
			goto end;
		} else if (n < 0) {
			INFO("%d: feed_stdin: errno=%d", ctx->client_identifier, errno);
			goto end;
		}
		ctx->script_ptr += n;
		ctx->script_len -= n;
		if (ctx->script_len == 0) {
			INFO("%d: all bytes sent to child's stdin", ctx->client_identifier);
			goto end;
		}
	}
	if (condition & G_IO_ERR) {
		// happens when previous writings were blocked, then the child process exited.
		INFO("%d: feed_stdin: G_IO_ERR", ctx->client_identifier);
		goto end;
	}
	if (!(condition & G_IO_OUT) && !(condition & G_IO_ERR)) {
		INFO("%d: feed_stdin: unexpected condition 0x%x", ctx->client_identifier, condition);
		goto end;
	}
	
	return G_SOURCE_CONTINUE;
end:
   	close(fd);
   	return G_SOURCE_REMOVE;
}

void watch_pid(GPid pid, gint wait_status, gpointer user_data)
{
	connection_context_t *ctx = (connection_context_t *)user_data;
	GError *error = NULL;
	gboolean is_success = g_spawn_check_wait_status(wait_status, &error);
	if (is_success) {
		INFO("%d: child terminated (pid=%d) ok", ctx->client_identifier, pid);
	} else {
		INFO("%d: child terminated (pid=%d) error: %s", ctx->client_identifier, pid, error->message);
		g_error_free(error);
	}
	g_free(ctx->bytes_received);
	g_free(ctx);
	g_spawn_close_pid(pid);
}

void execute_script(connection_context_t *ctx)
{
	GError *error = NULL;
	gint fd_stdin;
	GPid pid;
	char command_with_label[100];

	// Prefix all output lines of the bash script with the client identifier
	snprintf(command_with_label, 100, "bash 2>&1 | sed -e 's/^/%d: output: /'", ctx->client_identifier);
	gchar *command[] = {"bash", "-o", "pipefail", "-c", command_with_label, NULL};
	gboolean is_ok = g_spawn_async_with_pipes(NULL, command, NULL,
	                                          G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
	                                          NULL, NULL, &pid,
	                                          &fd_stdin, NULL, NULL,
	                                          &error);
	if (!is_ok) {
		INFO("%d: g_spawn_async_with_pipes error: %s\n", ctx->client_identifier, error->message);
		g_error_free(error);
	} else {
		INFO("%d: bash script started (pid=%d)", ctx->client_identifier, pid);
		g_unix_fd_add(fd_stdin, G_IO_OUT|G_IO_PRI|G_IO_ERR|G_IO_HUP, feed_stdin, (gpointer)ctx);
		g_child_watch_add(pid, watch_pid, (gpointer)ctx);
	}
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
		uint8_t buffer[10];
		ssize_t n;
		n = read(fd, buffer, sizeof(buffer)-1);
		if (n == 0) {
			// connection closed by peer
			INFO("%d: disconnected", client_id);
			goto close_fd;
		} else if (n < 1) {
			INFO("%d: read error: %s", client_id, g_strerror(errno));
			goto close_fd;
		} else if (n > 0) {
			buffer[n] = 0;
			DEBUG("%d: recv: %s", client_id, buffer); // assume printable characters only
			store(ctx, buffer, n);
		}
	}
	if (condition & G_IO_HUP) {
		INFO("%d: HUP", client_id);
		goto close_fd;
	}
	if (!(condition & G_IO_HUP) && !(condition & G_IO_IN)) {
		INFO("%d: unexpected condition 0x%x)", client_id, condition);
		goto close_fd;
	}

	return G_SOURCE_CONTINUE; // continue listening on this fd
close_fd:
	close(fd);
	if (0 == strncmp((char*)ctx->bytes_received, "shutdown\n", 9)) {
		INFO("%d: shutdown requested", client_id);
		g_main_loop_quit(ctx->general_context->mainloop);
		// not very clean shutdown as resources used by other connections
		// are not properly freed, and possible child processes running.
	} else {
		GError *error = NULL;
		const gchar *filename;
		int err = authenticate_script(ctx->bytes_received, ctx->bytes_received_len, ctx->general_context->public_keys, &filename, &error);
		if (err) {
			INFO("%d: authentication FAILED: %s", client_id, error->message);
			g_error_free(error);
		} else {
			INFO("%d: authentication OK by %s", client_id, filename);
			// start the script
			ctx->script_ptr = ctx->bytes_received; // the signature line can be executed as it is comment
			ctx->script_len = ctx->bytes_received_len;
			execute_script(ctx);
			return G_SOURCE_REMOVE; // stop monitoring this fd
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
		INFO("accept error: %s", g_strerror(errno));
		return G_SOURCE_CONTINUE; // continue listening
	}

	// allocate a client id for this connection
	connection_context_t *ctx = g_new0(connection_context_t, 1);
	ctx->general_context = general_context;
	ctx->client_identifier = next_client_id;
	next_client_id++;

	INFO("%d: new client connected", ctx->client_identifier);

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
		INFO("failed to create socket: %s", g_strerror(errno));
		return -1;
	}

	int sockflag = 1;
	err = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &sockflag, sizeof(sockflag));
	if (err) {
		INFO("setsockopt error: %s", g_strerror(errno));
	}

	// Configure the server address
	struct sockaddr_in sockin;
	sockin.sin_family = AF_INET;
	sockin.sin_port = htons(port);
	sockin.sin_addr.s_addr = INADDR_ANY;

	err = bind(listen_fd, (struct sockaddr *)&sockin, sizeof(sockin));
	if (err) {
		INFO("bind error: %s", g_strerror(errno));
		close(listen_fd);
		return -1;
	}

	err = listen(listen_fd, max_queue);
	if (err) {
		INFO("listen error: %s", g_strerror(errno));
		close(listen_fd);
		return -1;
	}
	return listen_fd;
}

int main(int argc, char **argv)
{
	if (argc < 3) return usage();

	uint16_t port = strtoul(argv[1], NULL, 10); // errors not handled

	GArray* public_keys = g_array_new(TRUE, TRUE, sizeof(public_key_t*));
	for (int i=2; i<argc; i++) {
		char *filename = argv[i];
		EVP_PKEY *pubkey = load_public_key(filename);
		if (!pubkey) continue;
		// we have a valid public key
		public_key_t *pubkey_struct = g_new0(public_key_t, 1);
		pubkey_struct->public_key = pubkey;
		pubkey_struct->filename = filename;
		g_array_append_val(public_keys, pubkey_struct);
		fprintf(stderr, "Pulic key loaded from %s\n", filename);
	}
	if (public_keys->len == 0) {
		fprintf(stderr, "No valid pulic key found\n");
		return 1;
	}

	int listen_fd = create_listening_socket(port);
	if (listen_fd < 0) return 1;

	INFO("Server listening on TCP port %u", port);

	// Ignore SIGPIPE, so that EPIPE errors on writing to stdin of child processes does not kill us
	signal(SIGPIPE, SIG_IGN);

	// Prepare the main event loop
	general_context_t ctx;
	ctx.mainloop = g_main_loop_new(NULL, FALSE);
	ctx.public_keys = public_keys;

	g_unix_fd_add(listen_fd, G_IO_IN, accept_incoming_connection, (gpointer)&ctx);

	// Start the main event loop
	g_main_loop_run(ctx.mainloop);

	// Clean up
	g_main_loop_unref(ctx.mainloop);
	close(listen_fd);

	// Free all public keys
	guint size = public_keys->len;
	for (guint i=0; i < size; i++) {
		public_key_t *pubkey_struct = g_array_index(public_keys, public_key_t*, i);
		EVP_PKEY_free(pubkey_struct->public_key);
		// Do not free the filename as it comes from the command line arguments
		g_free(pubkey_struct);
	}
	g_array_free(public_keys, TRUE);

	INFO("exiting");
	return 0;
}

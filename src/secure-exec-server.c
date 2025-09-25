
/*
 * Compile with:
 * gcc -o g_server_tcp g_server_tcp.c $(pkg-config --cflags --libs gio-2.0)
 *
 * Execution:
 * terminal-1> ./g_server_tcp 4455
 * Server listening on TCP port 4455
 *
 * terminal-2> socat - TCP:localhost:4455
 * hello
 *
 * terminal-1>
 * new client connected: 0
 * 0: recv: hello
 * 
 */

#include <arpa/inet.h>
#include <errno.h>
#include <glib-unix.h>
#include <stdio.h>
#include <sys/socket.h>

int usage()
{
	g_print("usage: g_server_tcp TCP-PORT\n");
	return 1;
}

void info(char *format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	
	fprintf(stderr, "\n");
}

typedef struct {
	int client_identifier;
	guint8 *bytes_received;
	size_t bytes_received_len;
} connection_context_t;


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
	g_free(ctx);
	return G_SOURCE_REMOVE; // stop monitoring this fd
}

gboolean accept_incoming_connection(gint fd, GIOCondition condition, gpointer user_data)
{
	static int next_client_id = 0;

	int client_fd = accept(fd, NULL, NULL);
	if (client_fd < 0) {
		info("accept error: %s", g_strerror(errno));
		return G_SOURCE_CONTINUE; // continue listening
	}
	
	// allocate a client id for this connection
	connection_context_t *ctx = g_new0(connection_context_t, 1);
	ctx->client_identifier = next_client_id;
	next_client_id++;

	info("new client connected: %d", ctx->client_identifier);

	g_unix_fd_add(client_fd, G_IO_IN|G_IO_PRI|G_IO_ERR|G_IO_HUP, receive_data, (gpointer)ctx);

	return G_SOURCE_CONTINUE; // continue listening
}

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
	if (argc != 2) return usage();

	guint16 port = strtoul(argv[1], NULL, 10); // errors not handled

	int listen_fd = create_listening_socket(port);
	if (listen_fd < 0) return 1;

	info("Server listening on TCP port %u", port);

	GMainLoop *loop;
	loop = g_main_loop_new(NULL, FALSE);
	g_unix_fd_add(listen_fd, G_IO_IN, accept_incoming_connection, NULL);
	g_main_loop_run(loop);

	g_main_loop_unref(loop);
	close(listen_fd);

	return 0;
}

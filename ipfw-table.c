#ifndef _WITH_GETLINE
// FreeBSD requires this to export getline(3).
#define _WITH_GETLINE
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include <err.h>
#include <sysexits.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_fw.h>

// This tool supports just addition and deletion of table entries.
enum op {
	NOP = 0,
	ADD,
	DEL
};

// The user can specify the table and default operation on the command line.
struct cli_args {
	enum op  default_op;
	uint16_t table;
};

// Each line starts with an optional operation ("add" or "del").
// followed by the key (IPv4 prefix, IPv6 prefix or interface)
// followed by an optional 32 bit value useable as integer or IPv4 address
// seperated by whitespaces.
struct line_args {
	enum op  op;
	uint8_t  type;
	uint8_t  masklen;
	uint32_t value;
	size_t   addrlen;
	union {
		struct in6_addr addr6;
		char            iface[IF_NAMESIZE];
	} key;
};



/**
 * Print a short usage line and terminate.
 **/
void
usage(const char *name)
{
	errx(EX_USAGE, "usage: %s (<add>|<del>) <table>", name);
}

// Define "add" and "del" as static constansts to reduce repition of literals.
static const char add[] = "add";
static const char del[] = "del";




/**
 * "Parse" an operation from a string.
 * Detects the operations ADD and DEL.
 * Everything else is mapped to NOP.
 **/
enum op
get_op(const char *input)
{
	if ( !input ) {
		return NOP;
	}

	if ( strncmp(input, add, strlen(add)) == 0 ) {
		return ADD;
	}

	if ( strncmp(input, del, strlen(del)) == 0 ) {
		return DEL;
	}

	return NOP;
}



/**
 * Get the maxium number of tables suppored by the kernel
 * via sysctl interface.
 **/
uint32_t
get_max_tables(void)
{
	const char sysctl_name[] = "net.inet.ip.fw.tables_max";
	uint32_t max_tables;
	size_t   sizeof_max_tables = sizeof(max_tables);

	if ( sysctlbyname(sysctl_name, &max_tables, &sizeof_max_tables, NULL, 0) == -1 ) {
		errx(EX_OSERR, "Can't read sysctl %s.", sysctl_name);
	}

	return max_tables;
}



/**
 * Convert a table number from decimal representation to unsigned integer
 * as expected by the IPFW socket interface.
 **/
static uint16_t
get_table(const char *input)
{
	const long long  min_tables = 0LL;
	const long long  max_tables = (long long)get_max_tables();
	const char      *error_msg;

	if ( max_tables < 1LL ) {
		errx(EX_OSERR, "The kernel supports less than one table.");
	}

	if ( max_tables > UINT16_MAX ) {
        	errx(EX_OSERR, "The kernel supports more tables than the API we use.");
	}

	const uint16_t table = (uint16_t)strtonum(input, min_tables, max_tables - 1, &error_msg);
	if ( error_msg != NULL ) {
		errx(EX_DATAERR, "Couldn't convert \"%s\" to a table number in range [%lld..%lld).",
				input, min_tables, max_tables);
	}

	return table;
}



/**
 * Parse and validate CLI provided parameters (table and defaul operation).
 * Terminate the process on errors.
 **/
struct cli_args
get_args(const int argc, const char *argv[])
{
	// check number of arguments
	if ( argc != 3 ) {
		usage(argv[0]); // doesn't return
	}

	// get default operation (add or delete)
	const enum op default_op = get_op(argv[1]);
	if ( default_op != ADD && default_op != DEL ) {
		usage(argv[0]); // doesn't return
	}
	
	// get table number
	const uint16_t table = get_table(argv[2]); // mightn't return

	const struct cli_args args = {
	       .default_op = default_op,
	       .table      = table
	};
	
	return args;
}

/**
 * Parse a line of input int a line_args struct. Exit process on errors.
 *
 * <add>     ::= "add"
 * <del>     ::= "del"
 * <value>   ::= <decimal> + # in range [0, UINT32_MAX]
 * <key>     ::= <ipv4> ( "/" <len4> )?
 *            |  <ipv6> ( "/" <len6> )?
 *            |  <interface>
 * <line> ::= ( <add> | <del> ) ? <key> <value> ?
 **/
struct line_args
get_line_args(char *line, enum op default_op)
{
	char     *token;
	struct   line_args args = { .type = 0 };

	enum { GET_OP, GET_KEY, GET_VALUE, IGNORE_REST } state = GET_OP;

	(void)default_op;
	while ( (token = strsep(&line, " \t\n")) != NULL ) {
		// zero length tokens resulting from e.g.
		// - multiple whitespaces
		// - trailing whitespace
		if ( strlen(token) == 0 ) {
			continue;
		}

		switch ( state ) {
			// Try to get the operation first.
			// Fallthrough to the key if neither "add" nor "del" is found.
			case GET_OP:
				args.op = get_op(token);
				if ( args.op == ADD || args.op == DEL ) {
					state = GET_KEY;
					break;
				}
				args.op = default_op;

			// Get the key to operate on.
			case GET_KEY: {
				// Copy potential interface name before modifing the token.
				size_t token_len = strlen(token);
			        char name[IF_NAMESIZE];
				strncpy(name, token, sizeof(name));

				// Split mask (if their is one)
				char *slash = strchr(token, '/');
				char *mask  = NULL;
				if ( slash != NULL ) {
                                       *slash = '\0';
				       mask   = slash + 1;
				}

				const char *error_msg;
				// Is the key an IPv4 addr?
				if ( inet_pton(AF_INET, token, &args.key.addr6) == 1 ) {
					args.type = IPFW_TABLE_CIDR;

					// Set mask length.
					if ( mask != NULL ) {
						args.masklen = (uint8_t)strtonum(mask, 0LL, 32LL, &error_msg);
						if ( error_msg ) {
                                                	errx(EX_DATAERR, "Address mask length %s: %s",
									error_msg, mask);
						}
					} else {
						args.masklen = 32;
					}
					args.addrlen = sizeof(struct in_addr);
				// Is the key an IPv6 addr?
				} else if ( inet_pton(AF_INET6, token, &args.key.addr6) == 1 ) {
					args.type = IPFW_TABLE_CIDR;
                                        
					// Set mask length.
					if ( mask != NULL ) {
						args.masklen = (uint8_t)strtonum(mask, 0LL, 128LL, &error_msg);
						if ( error_msg ) {
							errx(EX_DATAERR, "Address mask length %s: %s",
									error_msg, mask);
						}
					} else {
						args.masklen = 128;
					}
					args.addrlen = sizeof(struct in6_addr);
				// Assume the key is an interface name.
				} else {
					if ( token_len >= IF_NAMESIZE ) {
                                        	errx(EX_DATAERR, "Interface name \"%s\" is too long", token);
					}
					if ( token_len == 0 ) {
						errx(EX_DATAERR, "Interface name \"\" is too short");
					}

					args.masklen = CHAR_BIT * token_len;
					memset(&args.key, 0, sizeof(args.key));
					memcpy(args.key.iface, name, token_len);
					args.type = IPFW_TABLE_INTERFACE;
					args.addrlen = IF_NAMESIZE;
				}

				state = GET_VALUE;
				break;
		      	}
			
			case GET_VALUE: { 
				// Try to get a value for the table entry in the range of [0,UINT32_MAX].
				const char *error_msg = NULL;
				uint32_t value = strtonum(token, 0LL, (long long)UINT32_MAX, &error_msg);
				if ( error_msg ) {
                                	errx(EX_DATAERR, "Value %s is %s", token, error_msg);
				}
				args.value = value;
				state = IGNORE_REST;
				break;
			}

			// Silently ignore unused tokens.
			case IGNORE_REST:
			      break;
		}
	}

	if ( !args.type ) {
        	errx(EX_DATAERR, "Neither interface name nor IP address specified");
	}

	return args;
}

static int ipfw_socket = -1;

void
close_ipfw_socket(void)
{
	// Is their an IPFW socket to close?
	if ( ipfw_socket == -1 ) {
		return;
	}
	
	// Close the IPFW socket.
retry:
	if ( close(ipfw_socket) == 0 ) {
		ipfw_socket = -1;
		return;
	}
	// Retry if we get interrupted.
	if ( errno == EINTR ) {
		goto retry;
	}

	// Yes even errors during clean up deserve handling.
	err(EX_OSERR, "Failed to close IPFW socket");
}

void
modify_table(uint16_t table, const struct line_args *args)
{
	struct {
		ip_fw3_opheader   op3;
		ipfw_table_xentry xentry;
	} msg;

	// Open the IPFW socket if not yet opened.
	if ( ipfw_socket == -1 ) {
        	ipfw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if ( ipfw_socket < 0 ) {
			err(EX_UNAVAILABLE, "Failed to open IPFW socket");
		} else {
			// Close the socket before exit.
                	if ( atexit(close_ipfw_socket) != 0 ) {
				err(EX_OSERR, "Failed to register atexit handler");
			}
		}
	}

	// Clear potential padding and reserved bits.
	memset(&msg, 0, sizeof(msg));

	// Prepare the header with the operation to perform.
	switch ( args->op ) {
		case ADD:
			msg.op3.opcode = IP_FW_TABLE_XADD;
			break;

		case DEL:
			msg.op3.opcode = IP_FW_TABLE_XDEL;
			break;

		default:
			errx(EX_SOFTWARE, "You tried to perform neither an add nor a delete operation");
	}

	// Insert the arguments
	msg.xentry.len     = offsetof(ipfw_table_xentry, k) + args->addrlen,
	msg.xentry.type    = args->type,
	msg.xentry.masklen = args->masklen,
	msg.xentry.tbl     = table,
	msg.xentry.value   = args->value,
	memcpy(&msg.xentry.k, &args->key, sizeof(msg.xentry.k));

	if ( setsockopt(ipfw_socket, IPPROTO_IP, IP_FW3, &msg, sizeof(msg)) != 0 ) {
		switch ( errno ) {
			case EEXIST:
				warnx("Key already exists in table %d", table);
				break;

			case ESRCH:
				warnx("The key didn't exist in table %d", table);
				break;

			default:
				err(EX_SOFTWARE, "Failed to set socket option");
		}
	}
}	

int
loop(const struct cli_args *cli_args)
{
	char    *line          = NULL;
	size_t   line_capacity = 0;
	ssize_t  line_length;

	// Extract arguments from CLI args struct.
	const enum op  default_op = cli_args->default_op;
	const uint16_t table      = cli_args->table;

	// Read all lines from standard input.
	while ( (line_length = getline(&line, &line_capacity, stdin)) > 0 ) {
		// Parse input
		const struct line_args line_args = get_line_args(line, default_op);

		// Execute the parsed modification
		modify_table(table, &line_args);
	}
	if ( ferror(stdin) ) {
        	err(EX_IOERR,  "I/O error on standard input.");
	}
	if ( !feof(stdin) ) {
        	err(EX_SOFTWARE, "Failed to read all lines from standard input.");
	}
	return EX_OK;
}


int
main(int argc, const char *argv[])
{
	// Parse CLI arguments
        const struct cli_args args = get_args(argc, argv);

	// Run main loop.
	return loop(&args);
}

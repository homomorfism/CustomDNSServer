#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sqlite3.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>

#define BUF_SIZE 1500
/**
 * We use sqlite database to store domain names and IP addresses
 * */
sqlite3 *db;
char *err_msg = 0;
sqlite3_stmt *res;

static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x8000;
static const uint32_t RCODE_MASK = 0x000F;

/** Struct for the DNS Header */
typedef struct header {
    unsigned short id;
    unsigned char rd: 1;
    unsigned char tc: 1;
    unsigned char aa: 1;
    unsigned char opcode: 4;
    unsigned char qr: 1;
    unsigned char rcode: 4;
    unsigned char z: 3;
    unsigned char ra: 1;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} HEADER;
unsigned char rdata[10][254];

/** Struct for the flags for the DNS Question */
typedef struct q_flags {
    unsigned short qtype;
    unsigned short qclass;
} Q_FLAGS;

/** Struct for the flags for the DNS RRs */
typedef struct rr_flags {
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
} RR_FLAGS;

void get_dns_servers(char *str[]);

void change_to_dns_format(char *src, unsigned char *dest);

void change_to_dot_format(unsigned char *str);


/** Response Type */
enum {
    Ok_ResponseType = 0,
    FormatError_ResponseType = 1,
    ServerFailure_ResponseType = 2,
    NameError_ResponseType = 3,
    NotImplemented_ResponseType = 4,
    Refused_ResponseType = 5
};

/** Resource Record Types */
enum {
    A_Resource_RecordType = 1,
    NS_Resource_RecordType = 2,
    CNAME_Resource_RecordType = 5,
    SOA_Resource_RecordType = 6,
    PTR_Resource_RecordType = 12,
    MX_Resource_RecordType = 15,
    TXT_Resource_RecordType = 16,
    AAAA_Resource_RecordType = 28,
    SRV_Resource_RecordType = 33
};

/** Operation Code */
enum {
    QUERY_OperationCode = 0, /* standard query */
    IQUERY_OperationCode = 1, /* inverse query */
    STATUS_OperationCode = 2, /* server status request */
    NOTIFY_OperationCode = 4, /* request zone transfer */
    UPDATE_OperationCode = 5 /* change resource records */
};

/** Response Code */
enum {
    NoError_ResponseCode = 0,
    FormatError_ResponseCode = 1,
    ServerFailure_ResponseCode = 2,
    NameError_ResponseCode = 3
};

/** Query Type */
enum {
    IXFR_QueryType = 251,
    AXFR_QueryType = 252,
    MAILB_QueryType = 253,
    MAILA_QueryType = 254,
    STAR_QueryType = 255
};


/** Question Section */
struct Question {
    char *qName;
    uint16_t qType;
    uint16_t qClass;
    struct Question *next; // for linked list
};

/** Data part of a Resource Record */
union ResourceData {
    struct {
        uint8_t txt_data_len;
        char *txt_data;
    } txt_record;
    struct {
        uint8_t addr[4];
    } a_record;
    struct {
        char *MName;
        char *RName;
        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minimum;
    } soa_record;
    struct {
        char *name;
    } name_server_record;
    struct {
        char *name;
    } cname_record;
    struct {
        char *name;
    } ptr_record;
    struct {
        uint16_t preference;
        char *exchange;
    } mx_record;
    struct {
        uint8_t addr[16];
    } aaaa_record;
    struct {
        uint16_t priority;
        uint16_t weight;
        uint16_t port;
        char *target;
    } srv_record;
};

/** Resource Record Section */
struct ResourceRecord {
    char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rd_length;
    union ResourceData rd_data;
    struct ResourceRecord *next; // for linked list
};

struct Message {
    uint16_t id; /* Identifier */

    /* Flags */
    uint16_t qr; /* Query/Response Flag */
    uint16_t opcode; /* Operation Code */
    uint16_t aa; /* Authoritative Answer Flag */
    uint16_t tc; /* Truncation Flag */
    uint16_t rd; /* Recursion Desired */
    uint16_t ra; /* Recursion Available */
    uint16_t rcode; /* Response Code */

    uint16_t qdCount; /* Question Count */
    uint16_t anCount; /* Answer Record Count */
    uint16_t nsCount; /* Authority Record Count */
    uint16_t arCount; /* Additional Record Count */

    /* At least one question; questions are copied to the response 1:1 */
    struct Question *questions;

    /*
    * Resource records to be send back.
    * Every resource record can be in any of the following places.
    * But every place has a different semantic.
    */
    struct ResourceRecord *answers;
    struct ResourceRecord *authorities;
    struct ResourceRecord *additionals;
};

// Converting char ip address to char[]
union {
    unsigned int integer;
    unsigned char byte[4];
} itoch;

/** If IP address not in database, we connect to local server and retrieve IP from local server * */
int local(char *argv[]) {
    int argc = 2;

    HEADER *header_l = NULL;
    unsigned char *qname;
    Q_FLAGS *qflags = NULL;
    unsigned char name[10][254];
    RR_FLAGS *rrflags = NULL;
    unsigned int type[10];
    unsigned char packet[65536];
    unsigned char *temp;
    int i, j, steps = 0;

    /* Obtaining the DNS servers from the resolv.conf file */
    char **dns_addr = malloc(10 * sizeof(char *));
    for (i = 0; i < 10; ++i)
        dns_addr[i] = malloc(INET_ADDRSTRLEN);
    get_dns_servers(dns_addr);

    /* Building the Header portion of the query packet */
    header_l = (HEADER *) &packet;
    header_l->id = (unsigned short) htons(getpid());
    header_l->qr = 0;
    header_l->opcode = 0;
    header_l->aa = 0;
    header_l->tc = 0;
    header_l->rd = 1;
    header_l->ra = 0;
    header_l->z = 0;
    header_l->rcode = 0;
    header_l->qdcount = htons((unsigned short) (argc - 1));
    header_l->ancount = 0x0000;
    header_l->nscount = 0x0000;
    header_l->arcount = 0x0000;

    steps = sizeof(HEADER);

    /* Adding user-entered hostname into query packet and converting into DNS
    format */
    qname = (unsigned char *) &packet[steps];
    change_to_dns_format(argv[1], qname);

    steps = steps + (strlen((const char *) qname) + 1);

    /* Building the Question flags portion of the query packet */
    qflags = (Q_FLAGS *) &packet[steps];
    qflags->qtype = htons(0x0001);
    qflags->qclass = htons(0x0001);

    steps = steps + sizeof(Q_FLAGS);

    /* Building the socket for connecting to the DNS server */
    long sock_fd;
    struct sockaddr_in servaddr;
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(53);
    inet_pton(AF_INET, dns_addr[0], &(servaddr.sin_addr));

    /* Connecting to the DNS server */
    connect(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));

    /* Sending the query packet to the DNS server */
    write(sock_fd, (unsigned char *) packet, steps);

    /* Receiving the response packet from the DNS server */
    if (read(sock_fd, (unsigned char *) packet, 65536) <= 0)
        close(sock_fd);
    for (i = 0; i < 10; ++i)
        free(dns_addr[i]);
    free(dns_addr);

    /* Parsing the Header portion of the reply packet */
    header_l = (HEADER *) &packet;
    steps = sizeof(HEADER);

    /* Parsing the QNAME portion of the reply packet */
    qname = (unsigned char *) &packet[steps];
    change_to_dot_format(qname);
    steps = steps + (strlen((const char *) qname) + 2);

    /* Parsing the Question flags portion of the reply packet */
    qflags = (Q_FLAGS *) &packet[steps];
    steps = steps + sizeof(Q_FLAGS);

    /* Parsing the RRs from the reply packet */
    for (i = 0; i < ntohs(header_l->ancount); ++i) {

        /* Parsing the NAME portion of the RR */
        temp = (unsigned char *) &packet[steps];
        j = 0;
        while (*temp != 0) {
            if (*temp == 0xc0) {
                ++temp;
                temp = (unsigned char *) &packet[*temp];
            } else {
                name[i][j] = *temp;
                ++j;
                ++temp;
            }
        }
        name[i][j] = '\0';
        change_to_dot_format(name[i]);
        steps = steps + 2;

        /* Parsing the RR flags of the RR */
        rrflags = (RR_FLAGS *) &packet[steps];
        steps = steps + sizeof(RR_FLAGS) - 2;

        /* Parsing the IPv4 address in the RR */
        if (ntohs(rrflags->type) == 1) {
            for (j = 0; j < ntohs(rrflags->rdlength); ++j)
                rdata[i][j] = (unsigned char) packet[steps + j];
            type[i] = ntohs(rrflags->type);
        }

        /* Parsing the canonical name in the RR */
        if (ntohs(rrflags->type) == 5) {
            temp = (unsigned char *) &packet[steps];
            j = 0;
            while (*temp != 0) {
                if (*temp == 0xc0) {
                    ++temp;
                    temp = (unsigned char *) &packet[*temp];
                } else {
                    rdata[i][j] = *temp;
                    ++j;
                    ++temp;
                }
            }
            rdata[i][j] = '\0';
            change_to_dot_format(rdata[i]);
            type[i] = ntohs(rrflags->type);
        }
        steps = steps + ntohs(rrflags->rdlength);
    }

    return 0;
}

void get_dns_servers(char *str[]) {

    FILE *resolv_file;
    char line[100];
    int i = 0;

    resolv_file = fopen("/etc/resolv.conf", "rt");

    while (fgets(line, 100, resolv_file)) {
        if (strncmp(line, "nameserver", 10) == 0) {
            strcpy(str[i], strtok(line, " "));
            strcpy(str[i], strtok(NULL, "\n"));
            ++i;
        }
    }

    fclose(resolv_file);
}

/* The function converts the dot-based hostname into the DNS format (i.e.
www.apple.com into 3www5apple3com0) */
void change_to_dns_format(char *src, unsigned char *dest) {
    int pos = 0;
    int len = 0;
    int i;
    char new_src[100];
    strcpy(new_src, src);
    strcat(new_src, ".");
    for (i = 0; i < (int) strlen(new_src); ++i) {
        if (new_src[i] == '.') {
            dest[pos] = i - len;
            ++pos;
            for (; len < i; ++len) {
                dest[pos] = new_src[len];
                ++pos;
            }
            len++;
        }
    }
    dest[pos] = '\0';
}

/** This function converts a DNS-based hostname into dot-based format (i.e.
3www5apple3com0 into www.apple.com) */
void change_to_dot_format(unsigned char *str) {
    int i, j;
    for (i = 0; i < strlen((const char *) str); ++i) {
        unsigned int len = str[i];
        for (j = 0; j < len; ++j) {
            str[i] = str[i + 1];
            ++i;
        }
        str[i] = '.';
    }
    str[i - 1] = '\0';
}

/**
 * Function retrieve IP address from the database. If IP is not present in database, we connect to local server throughout
 * function local */
int get_A_Record_from_sqlite(u_int8_t addr[4], const char domain_name[]) {

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(
            db,
            "SELECT ip1, ip2, ip3, ip4 from ARecords where domain_name = ? ;",
            -1,
            &stmt,
            NULL
    );
    sqlite3_bind_text(stmt, 1, domain_name, -1, SQLITE_STATIC);

    int ip1 = 0, ip2 = 0, ip3 = 0, ip4 = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ip1 = (int) sqlite3_column_int(stmt, 0);
        ip2 = (int) sqlite3_column_int(stmt, 1);
        ip3 = (int) sqlite3_column_int(stmt, 2);
        ip4 = (int) sqlite3_column_int(stmt, 3);
    }

    if (ip1 == 0 && ip2 == 0 && ip3 == 0 && ip4 == 0) {
        char *argv[2] = {(char *) domain_name, (char *) domain_name};
        local(argv);
        ip1 = rdata[1][0];
        ip2 = rdata[1][1];
        ip3 = rdata[1][2];
        ip4 = rdata[1][3];
        if (ip1 == 0 && ip2 == 0 && ip3 == 0 && ip4 == 0) {
            printf("\nThe domain name is not valid. Please try again.\n");
            exit(0);
        }
        sqlite3_stmt *insert;
        sqlite3_prepare_v2(
                db,
                "INSERT INTO ARecords VALUES (?, ?, ?, ?, ?);",
                -1,
                &insert,
                NULL);

        sqlite3_bind_text(insert, 1, (char *) domain_name, -1, SQLITE_STATIC);
        sqlite3_bind_int(insert, 2, ip1);
        sqlite3_bind_int(insert, 3, ip2);
        sqlite3_bind_int(insert, 4, ip3);
        sqlite3_bind_int(insert, 5, ip4);
        sqlite3_step(insert);

    }


    printf("IP is : %d.%d.%d.%d \n", ip1, ip2, ip3, ip4);

    addr[0] = ip1;
    addr[1] = ip2;
    addr[2] = ip3;
    addr[3] = ip4;

    return 0;
}

void print_resource_record(struct ResourceRecord *rr) {
    int i;
    while (rr) {
        printf("ResourceRecord { name '%s', type %u, class %u, ttl %u, rd_length %u, ",
               rr->name,
               rr->type,
               rr->class,
               rr->ttl,
               rr->rd_length
        );

        union ResourceData *rd = &rr->rd_data;
        switch (rr->type) {
            case A_Resource_RecordType:
                printf("Address Resource Record { address ");

                for (i = 0; i < 4; ++i)
                    printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);

                printf(" }");
                break;
            case NS_Resource_RecordType:
                printf("Name Server Resource Record { name %s }",
                       rd->name_server_record.name
                );
                break;
            case CNAME_Resource_RecordType:
                printf("Canonical Name Resource Record { name %s }",
                       rd->cname_record.name
                );
                break;
            case SOA_Resource_RecordType:
                printf("SOA { MName '%s', RName '%s', serial %u, refresh %u, retry %u, expire %u, minimum %u }",
                       rd->soa_record.MName,
                       rd->soa_record.RName,
                       rd->soa_record.serial,
                       rd->soa_record.refresh,
                       rd->soa_record.retry,
                       rd->soa_record.expire,
                       rd->soa_record.minimum
                );
                break;
            case PTR_Resource_RecordType:
                printf("Pointer Resource Record { name '%s' }",
                       rd->ptr_record.name
                );
                break;
            case MX_Resource_RecordType:
                printf("Mail Exchange Record { preference %u, exchange '%s' }",
                       rd->mx_record.preference,
                       rd->mx_record.exchange
                );
                break;
            case TXT_Resource_RecordType:
                printf("Text Resource Record { txt_data '%s' }",
                       rd->txt_record.txt_data
                );
                break;
            case AAAA_Resource_RecordType:
                printf("AAAA Resource Record { address ");

                for (i = 0; i < 16; ++i)
                    printf("%s%02x", (i ? ":" : ""), rd->aaaa_record.addr[i]);

                printf(" }");
                break;
            default:
                printf("Unknown Resource Record { ??? }");
        }
        printf("}\n");
        rr = rr->next;

    }
}

void print_query(struct Message *msg) {
    struct Question *q;
    q = msg->questions;
    while (q) {
        q = q->next;
    }

    print_resource_record(msg->answers);
    print_resource_record(msg->authorities);
    print_resource_record(msg->additionals);
}


/**
* Basic memory operations.
*/

size_t get16bits(const uint8_t **buffer) {
    uint16_t value;

    memcpy(&value, *buffer, 2);
    *buffer += 2;

    return ntohs(value);
}

void put8bits(uint8_t **buffer, uint8_t value) {
    memcpy(*buffer, &value, 1);
    *buffer += 1;
}

void put16bits(uint8_t **buffer, uint16_t value) {
    value = htons(value);
    memcpy(*buffer, &value, 2);
    *buffer += 2;
}

void put32bits(uint8_t **buffer, uint32_t value) {
    value = htonl(value);
    memcpy(*buffer, &value, 4);
    *buffer += 4;
}

char *decode_domain_name(const uint8_t **buffer) {
    char name[256];
    const uint8_t *buf = *buffer;
    int j = 0;
    int i = 0;

    while (buf[i] != 0) {

        if (i != 0) {
            name[j] = '.';
            j += 1;
        }

        int len = buf[i];
        i += 1;

        memcpy(name + j, buf + i, len);
        i += len;
        j += len;
    }

    name[j] = '\0';

    *buffer += i + 1; //also jump over the last 0

    return strdup(name);
}

void encode_domain_name(uint8_t **buffer, const char *domain) {
    uint8_t *buf = *buffer;
    const char *beg = domain;
    const char *pos;
    int len = 0;
    int i = 0;

    while ((pos = strchr(beg, '.'))) {
        len = pos - beg;
        buf[i] = len;
        i += 1;
        memcpy(buf + i, beg, len);
        i += len;

        beg = pos + 1;
    }

    len = strlen(domain) - (beg - domain);

    buf[i] = len;
    i += 1;

    memcpy(buf + i, beg, len);
    i += len;

    buf[i] = 0;
    i += 1;

    *buffer += i;
}


void decode_header(struct Message *msg, const uint8_t **buffer) {
    msg->id = get16bits(buffer);

    uint32_t fields = get16bits(buffer);
    msg->qr = (fields & QR_MASK) >> 15;
    msg->opcode = (fields & OPCODE_MASK) >> 11;
    msg->aa = (fields & AA_MASK) >> 10;
    msg->tc = (fields & TC_MASK) >> 9;
    msg->rd = (fields & RD_MASK) >> 8;
    msg->ra = (fields & RA_MASK) >> 7;
    msg->rcode = (fields & RCODE_MASK) >> 0;

    msg->qdCount = get16bits(buffer);
    msg->anCount = get16bits(buffer);
    msg->nsCount = get16bits(buffer);
    msg->arCount = get16bits(buffer);
}

void encode_header(struct Message *msg, uint8_t **buffer) {
    put16bits(buffer, msg->id);

    int fields = 0;
    fields |= (msg->qr << 15) & QR_MASK;
    fields |= (msg->rcode << 0) & RCODE_MASK;
    put16bits(buffer, fields);

    put16bits(buffer, msg->qdCount);
    put16bits(buffer, msg->anCount);
    put16bits(buffer, msg->nsCount);
    put16bits(buffer, msg->arCount);
}

int decode_msg(struct Message *msg, const uint8_t *buffer, int size) {
    int i;

    decode_header(msg, &buffer);

    if (msg->anCount != 0 || msg->nsCount != 0) {
        printf("Only questions expected!\n");
        return -1;
    }

    // parse questions
    uint32_t qcount = msg->qdCount;
    for (i = 0; i < qcount; ++i) {
        struct Question *q = malloc(sizeof(struct Question));

        q->qName = decode_domain_name(&buffer);
        q->qType = get16bits(&buffer);
        q->qClass = get16bits(&buffer);

        // prepend question to questions list
        q->next = msg->questions;
        msg->questions = q;
    }

    return 0;
}

void resolver_process(struct Message *msg) {
    struct ResourceRecord *beg;
    struct ResourceRecord *rr;
    struct Question *q;
    int rc;

    // leave most values intact for response
    msg->qr = 1; // this is a response
    msg->aa = 1; // this server is authoritative
    msg->ra = 0; // no recursion available
    msg->rcode = Ok_ResponseType;

    // should already be 0
    msg->anCount = 0;
    msg->nsCount = 0;
    msg->arCount = 0;

    // for every question append resource records
    q = msg->questions;
    while (q) {
        rr = malloc(sizeof(struct ResourceRecord));
        memset(rr, 0, sizeof(struct ResourceRecord));

        rr->name = strdup(q->qName);
        rr->type = q->qType;
        rr->class = q->qClass;
        rr->ttl = 60 * 60; // in seconds; 0 means no caching

        printf("Query for '%s'\n", q->qName);

        // A - record type
        switch (q->qType) {
            case A_Resource_RecordType:
                rr->rd_length = 4;
                rc = get_A_Record_from_sqlite(rr->rd_data.a_record.addr, q->qName);
                if (rc < 0) {
                    free(rr->name);
                    free(rr);
                    goto next;
                }
                break;
        }
        msg->anCount++;

        // prepend resource record to answers list
        beg = msg->answers;
        msg->answers = rr;
        rr->next = beg;

        // jump here to omit question
        next:

        // process next question
        q = q->next;
    }
}

/* @return 0 upon failure, 1 upon success */
int encode_resource_records(struct ResourceRecord *rr, uint8_t **buffer) {
    int i;
    while (rr) {
        // Answer questions by attaching resource sections.
        encode_domain_name(buffer, rr->name);
        put16bits(buffer, rr->type);
        put16bits(buffer, rr->class);
        put32bits(buffer, rr->ttl);
        put16bits(buffer, rr->rd_length);

        switch (rr->type) {
            case A_Resource_RecordType:
                for (i = 0; i < 4; ++i)
                    put8bits(buffer, rr->rd_data.a_record.addr[i]);
                break;
        }

        rr = rr->next;
    }

    return 0;
}

/* @return 0 upon failure, 1 upon success */
int encode_msg(struct Message *msg, uint8_t **buffer) {
    struct Question *q;
    int rc;

    encode_header(msg, buffer);

    q = msg->questions;
    while (q) {
        encode_domain_name(buffer, q->qName);
        put16bits(buffer, q->qType);
        put16bits(buffer, q->qClass);

        q = q->next;
    }

    rc = 0;
    rc |= encode_resource_records(msg->answers, buffer);
    rc |= encode_resource_records(msg->authorities, buffer);
    rc |= encode_resource_records(msg->additionals, buffer);

    return rc;
}

void free_resource_records(struct ResourceRecord *rr) {
    struct ResourceRecord *next;

    while (rr) {
        free(rr->name);
        next = rr->next;
        free(rr);
        rr = next;
    }
}

void free_questions(struct Question *qq) {
    struct Question *next;

    while (qq) {
        free(qq->qName);
        next = qq->next;
        free(qq);
        qq = next;
    }
}


int main() {
    int rc_ = sqlite3_open("database.db", &db);
    if (rc_ != SQLITE_OK) {

        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);

        return 1;
    }

    // buffer for input/output binary packet
    uint8_t buffer[BUF_SIZE];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    int nbytes, rc;
    int sock;
    int port = 9000;

    struct Message msg;
    memset(&msg, 0, sizeof(struct Message));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    rc = bind(sock, (struct sockaddr *) &addr, addr_len);

    if (rc != 0) {
        printf("Could not bind: %s\n", strerror(errno));
        return 1;
    }

    printf("Use 'dig @ip -p 9000 domain name A' command in other terminal \nListening on port %u.\n \n", port);

    while (1) {
        free_questions(msg.questions);
        free_resource_records(msg.answers);
        free_resource_records(msg.authorities);
        free_resource_records(msg.additionals);
        memset(&msg, 0, sizeof(struct Message));

        nbytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, &addr_len);

        if (decode_msg(&msg, buffer, nbytes) != 0) {
            continue;
        }

        /* Print query */
        print_query(&msg);

        resolver_process(&msg);

        /* Print response */
        print_query(&msg);

        uint8_t *p = buffer;
        if (encode_msg(&msg, &p) != 0) {
            continue;
        }
        int buflen = p - buffer;
        sendto(sock, buffer, buflen, 0, (struct sockaddr *) &client_addr, addr_len);
        return 0;
    }
}

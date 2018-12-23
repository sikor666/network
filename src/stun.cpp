#include "unp.h"

#include <iostream>
#include <map>
#include <string>

// Format of STUN Message Header
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//| 0 0 |    STUN Message Type    |        Message Length         |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                         Magic Cookie                          |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                                                               |
//|                     Transaction ID(96 bits)                   |
//|                                                               |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Format of STUN Message Type Field
// 0                 1           
// 2  3  4  5  6  7  8  9  0  1  2  3  4  5
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//| M| M| M| M| M| C| M| M| M| C| M| M| M| M|
//|11|10| 9| 8| 7| 1| 6| 5| 4| 0| 3| 2| 1| 0|
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// Format of STUN Attributes
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|             Type              |            Length             |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                          Value (variable)                  ....
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Format of MAPPED-ADDRESS Attribute
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|0 0 0 0 0 0 0 0|     Family    |             Port              |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                                                               |
//|                Address (32 bits or 128 bits)                  |
//|                                                               |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Format of XOR-MAPPED-ADDRESS Attribute
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|x x x x x x x x|     Family    |            X-Port             |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                      X-Address (Variable)                  ....
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

enum class AttributeType : u_short
{
    //Comprehension - required range (0x0000-0x7FFF):
    None              = 0x0000, //: (Reserved)
    MappedAddress     = 0x0001, //: MAPPED-ADDRESS
    ResponseAddress   = 0x0002, //: (Reserved; was RESPONSE-ADDRESS)
    ChangeAddress     = 0x0003, //: (Reserved; was CHANGE-ADDRESS)
    SourceAddress     = 0x0004, //: (Reserved; was SOURCE-ADDRESS)
    ChangedAddress    = 0x0005, //: (Reserved; was CHANGED-ADDRESS)
    Username          = 0x0006, //: USERNAME
    Password          = 0x0007, //: (Reserved; was PASSWORD)
    MessageIntegrity  = 0x0008, //: MESSAGE-INTEGRITY
    ErrorCode         = 0x0009, //: ERROR-CODE
    UnknownAttributes = 0x000A, //: UNKNOWN-ATTRIBUTES
    ReflectedFrom     = 0x000B, //: (Reserved; was REFLECTED-FROM)
    Realm             = 0x0014, //: REALM
    Nonce             = 0x0015, //: NONCE
    XorMappedAddress  = 0x0020, //: XOR-MAPPED-ADDRESS

    //Comprehension - optional range (0x8000-0xFFFF):
    XorMappedAddress2 = 0x8020, //: XOR-MAPPED-ADDRESS-2
    Software          = 0x8022, //: SOFTWARE
    AlternateServer   = 0x8023, //: ALTERNATE-SERVER
    Fingerprint       = 0x8028, //: FINGERPRINT
};

std::map<AttributeType, std::string> attributeTypes
{
    { AttributeType::None, "" },
    { AttributeType::MappedAddress, "MAPPED-ADDRESS" },
    { AttributeType::ResponseAddress, "RESPONSE-ADDRESS" },
    { AttributeType::ChangeAddress, "CHANGE-ADDRESS" },
    { AttributeType::SourceAddress, "SOURCE-ADDRESS" },
    { AttributeType::ChangedAddress, "CHANGED-ADDRESS" },
    { AttributeType::Username, "USERNAME" },
    { AttributeType::Password, "PASSWORD" },
    { AttributeType::MessageIntegrity, "MESSAGE-INTEGRITY" },
    { AttributeType::ErrorCode, "ERROR-CODE" },
    { AttributeType::UnknownAttributes, "UNKNOWN-ATTRIBUTES" },
    { AttributeType::ReflectedFrom, "REFLECTED-FROM" },
    { AttributeType::Realm, "REALM" },
    { AttributeType::Nonce, "NONCE" },
    { AttributeType::XorMappedAddress, "XOR-MAPPED-ADDRESS" },

    { AttributeType::XorMappedAddress2, "XOR-MAPPED-ADDRESS-2" },
    { AttributeType::Software, "SOFTWARE" },
    { AttributeType::AlternateServer, "ALTERNATE-SERVER" },
    { AttributeType::Fingerprint, "FINGERPRINT" },
};

constexpr u_char IPv4 = 0x01;
constexpr u_char IPv6 = 0x02;

std::map<u_char, std::string> addressFamily
{
    { IPv4, "IPv4" },
    { IPv6, "IPv6" },
};

#define IS_REQUEST(msg_type)       (((msg_type) & 0x0110) == 0x0000)
#define IS_INDICATION(msg_type)    (((msg_type) & 0x0110) == 0x0010)
#define IS_SUCCESS_RESP(msg_type)  (((msg_type) & 0x0110) == 0x0100)
#define IS_ERR_RESP(msg_type)      (((msg_type) & 0x0110) == 0x0110)

#pragma pack (push, 4)
struct StunHeader
{
    u_short type;
    u_short length;
    u_int cookie;
    u_int tid[3];
};

struct StunAttribute
{
    u_short type;
    u_short length;
};

struct StunAddrVariable
{
    u_char zero;
    u_char family;
    u_short port;
    u_int address[4];
};
#pragma pack (pop)

int main(int argc, char **argv)
{
    init();

    int                 sockfd;
    size_t              n;
    socklen_t           salen;
    struct sockaddr     *sa;
    char recvline[MAXLINE + 1];
    char variable[MAXLINE + 1];

    StunHeader header;
    *(&header.type)   = htons(0x0001);      //Message Type : 0x0001 (Binding Request)
                      //.... ...0 ...0 .... = Message Class : 0x00 Request(0)
                      //..00 000. 000. 0001 = Message Method : 0x0001 Binding(0x001)
                      //..0. .... .... .... = Message Method Assignment : IETF Review(0x0)

    *(&header.length) = htons(0x0000);      //Message Length : 0
    *(&header.cookie) = htonl(0x2112A442);  //Message Cookie : 2112a442

    *(&header.tid[0]) = htonl(0x00000000); //Message Transaction ID : 000000000000000000000000
    *(&header.tid[1]) = htonl(0x00000000); //Random
    *(&header.tid[2]) = htonl(0x00000000);

    sockfd = Udp_client(STUN_ADDR, STUN_PORT, &sa, &salen);
    Sendto(sockfd, &header, sizeof(header), 0, sa, salen);

    n = Recvfrom(sockfd, recvline, MAXLINE, 0, nullptr, nullptr);
    recvline[n] = 0; // null terminate

    size_t offset = 0;
    memcpy(reinterpret_cast<void *>(&header), recvline, sizeof(header));
    offset += sizeof(header);

    while (n > offset)
    {
        StunAttribute attribute;
        memcpy(reinterpret_cast<char *>(&attribute), recvline + offset, sizeof(attribute));
        offset += sizeof(attribute);

        auto type = static_cast<AttributeType>(ntohs(attribute.type));
        auto length = ntohs(attribute.length);

        memcpy(variable, recvline + offset, length);
        offset += length;
        variable[length] = 0;

        switch (type)
        {
        case AttributeType::MappedAddress:
        case AttributeType::SourceAddress:
        case AttributeType::ChangedAddress:
        case AttributeType::XorMappedAddress:
        case AttributeType::XorMappedAddress2:
        {
            StunAddrVariable addrVariable;
            memcpy(&addrVariable, variable, length);

            std::cout << attributeTypes[type] << std::endl;
            std::cout << "\t family: " << addressFamily[addrVariable.family] << std::endl;

            auto port = type == AttributeType::XorMappedAddress ||
                        type == AttributeType::XorMappedAddress2 ?
                ntohs(addrVariable.port ^ header.cookie) :
                ntohs(addrVariable.port);

            std::cout << "\t port: " << port << std::endl;

            if (addrVariable.family == IPv4)
            {
                struct in_addr addr;
                addr.s_addr = type == AttributeType::XorMappedAddress ||
                              type == AttributeType::XorMappedAddress2 ?
                    addrVariable.address[0] ^ header.cookie :
                    addrVariable.address[0];

                static char str[128];

                if (inet_ntop(AF_INET, &addr, str, sizeof(str)) != nullptr)
                {
                    std::cout << "\t address: " << str << std::endl;
                }
            }

            break;
        }
        default:
            std::cout << attributeTypes[type] << ": " << variable << std::endl;
            break;
        }
    }

    free(sa);

    clean();

#if defined _WIN32
    std::system("pause");
#endif

    return 0;
}

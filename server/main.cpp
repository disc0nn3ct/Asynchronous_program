#include <iostream>
#include "gen.hpp"
#include <boost/asio.hpp>


class m_session : public std::enable_shared_from_this<m_session>
{
public:
    m_session(boost::asio::ip::tcp::socket m_in_socket, uint m_buffer_size)
        : in_socket(std::move(m_in_socket)),
          out_socket(m_in_socket.get_executor()),
          in_buf(m_buffer_size),
          out_buf(m_buffer_size),
          resolver(m_in_socket.get_executor())

    {
    }
    void start()
    {
        std::cout<< "start\n " <<std::endl;
        read_handshake_sock5();
    }


private:
//    +----+----------+----------+
//    |VER | NMETHODS | METHODS  |
//    +----+----------+----------+
//    | 1  |    1     | 1 to 255 |
//    +----+----------+----------+
//    o  X'00' NO AUTHENTICATION REQUIRED
//    o  X'01' GSSAPI
//    o  X'02' USERNAME/PASSWORD
//    o  X'03' to X'7F' IANA ASSIGNED
//    o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
//    o  X'FF' NO ACCEPTABLE METHODS
// VER = 0x05 ONLY

    void read_handshake_sock5() // VER 1, NMETHODS 1, METHODS 1-255  // METHODS = X'00' NO AUTHENTICATION REQUIRED
    {
        auto self(shared_from_this());

        in_socket.async_receive(boost::asio::buffer(in_buf),
            [this, self](boost::system::error_code ec, std::size_t len)
        {
            if (!ec)
            {
                if(len < 3 || in_buf[0] != 0x05)
                {
                    return;
                }
            ////////////////////////////////
//            for(int i=0; i < 5; i++)
//            {
//                printf("%d = %X\n",i, in_buf[i]);
//            }
            /////////////////////////////////
            uint8_t NMETHODS = in_buf[1];
            in_buf[1] = 0xFF;
            //
            for(uint8_t METHODS=0; METHODS < NMETHODS; METHODS++)
                if (in_buf[2+METHODS] == 0x00)
                {
                    in_buf[1]=0x00;
                    break;
                }
            write_handshake_sock5();
            }
        }
        );
    }

    void write_handshake_sock5()
    {
        auto self(shared_from_this());
        boost::asio::async_write(in_socket, boost::asio::buffer(in_buf, 2),
            [this, self](boost::system::error_code ec, std::size_t len)
        {
            if (!ec)
            {
                if (in_buf[1] == 0xFF)
                    return -1;
                read_request_socks5();
            }
        });
    }


//    +----+-----+-------+------+----------+----------+
//    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//    +----+-----+-------+------+----------+----------+
//    | 1  |  1  | X'00' |  1   | Variable |    2     |
//    +----+-----+-------+------+----------+----------+
//    Where:

//         o  VER    protocol version: X'05'
//         o  CMD
//            o  CONNECT X'01'
//            o  BIND X'02'
//            o  UDP ASSOCIATE X'03'
//         o  RSV    RESERVED
//         o  ATYP   address type of following address
//            o  IP V4 address: X'01'
//            o  DOMAINNAME: X'03'
//            o  IP V6 address: X'04'
//         o  DST.ADDR       desired destination address
//         o  DST.PORT desired destination port in network octet
//            order
//    The SOCKS server will typically evaluate the request based on source
//    and destination addresses, and return one or more reply messages, as
//    appropriate for the request type.
//    o  X'01'
//the address is a version-4 IP address, with a length of 4 octets
//    o  X'03'


    void read_request_socks5()
    {
        auto self(shared_from_this());
        in_socket.async_receive(boost::asio::buffer(in_buf),
            [this, self](boost::system::error_code ec, std::size_t len)
            {
                if (!ec)
                {
                    if (len < 5 || in_buf[0] != 0x05 || in_buf[1] != 0x01)
                        return -1;
///////////////////////////////

                    uint8_t addr_type = in_buf[3], host_len;

                    switch (addr_type)
                    {
                    case 0x01: // IP v4 addres
                        if (len != 10) { return -1; }
//                        ///////////////////////////////
//                        printf(" in_buf[4] =============== %X\n", in_buf[4]);
//                        printf(" &in_buf[4] =============== %X\n", &in_buf[4]);
//                        printf(" (uint32_t*)&in_buf[4]=============== %X\n", (uint32_t*)&in_buf[4]);
//                        printf(" *((uint32_t*)&in_buf[4]) =============== %X\n", *((uint32_t*)&in_buf[4]));
//                        printf(" ntohl(*((uint32_t*)&in_buf[4]))) =============== %X\n", ntohl(*((uint32_t*)&in_buf[4])));
//                        printf(" boost::asio::ip::address_v4(ntohl(*((uint32_t*)&in_buf[4]))) =============== %X\n", boost::asio::ip::address_v4(ntohl(*((uint32_t*)&in_buf[4]))));


//                        std::cout << "--------------------- " << (uint32_t*)&in_buf[4] << std::endl;
//                        std::cout << "in_buf[4] --------------------- " << in_buf[4] << std::endl;

//                        ///////////////////////////////
                        remote_host = boost::asio::ip::address_v4(ntohl(*((uint32_t*)&in_buf[4]))).to_string();
                        remote_port = std::to_string(ntohs(*((uint16_t*)&in_buf[8])));
                        break;
                    case 0x03: // domainname
                        host_len = in_buf[4];
                        if (len != (size_t)(5 + host_len + 2))
                        {
                            return -1;
                        }
                        remote_host = std::string(&in_buf[5], host_len);
                        remote_port = std::to_string(ntohs(*((uint16_t*)&in_buf[5 + host_len])));
                        break;
                    default:
                        break;
                    }
                std::cout<< "remote_host = " << remote_host  << std::endl;
//                std::cout<< "remote_port = " << remote_port << std::endl;
                    do_resolve();



                }
        });



    }
///////////////////////////////======================================
    void do_resolve()
    {
        auto self(shared_from_this());

        resolver.async_resolve(boost::asio::ip::tcp::resolver::query({remote_host, remote_port}),
            [this, self](const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::iterator it)
            {
                if (!ec)
                {
                    do_connect(it);
                }
                else
                {
                    std::ostringstream what; what << "failed to resolve " << remote_host << ":" << remote_port;
                }
            });
    }

    void do_connect(boost::asio::ip::tcp::resolver::iterator& it)
    {
        auto self(shared_from_this());
        out_socket.async_connect(*it,
            [this, self](const boost::system::error_code& ec)
            {
                if (!ec)
                {
                    std::ostringstream what; what << "connected to " << remote_host << ":" << remote_port;
                    write_socks5_response();
                }
                else
                {
                    std::ostringstream what; what << "failed to connect " << remote_host << ":" << remote_port;

                }
            });

    }



    //   The SOCKS request information is sent by the client as soon as it has
    //   established a connection to the SOCKS server, and completed the
    //   authentication negotiations.  The server evaluates the request, and
    //   returns a reply formed as follows:

    //        +----+-----+-------+------+----------+----------+
    //        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //        +----+-----+-------+------+----------+----------+
    //        | 1  |  1  | X'00' |  1   | Variable |    2     |
    //        +----+-----+-------+------+----------+----------+

    //     Where:

    //          o  VER    protocol version: X'05'
    //          o  REP    Reply field:
    //             o  X'00' succeeded
    //             o  X'01' general SOCKS server failure
    //             o  X'02' connection not allowed by ruleset
    //             o  X'03' Network unreachable
    //             o  X'04' Host unreachable
    //             o  X'05' Connection refused
    //             o  X'06' TTL expired
    //             o  X'07' Command not supported
    //             o  X'08' Address type not supported
    //             o  X'09' to X'FF' unassigned
    //          o  RSV    RESERVED
    //          o  ATYP   address type of following address
    //        o  IP V4 address: X'01'
    //        o  DOMAINNAME: X'03'
    //        o  IP V6 address: X'04'
    //     o  BND.ADDR       server bound address
    //     o  BND.PORT       server bound port in network octet order

    //Fields marked RESERVED (RSV) must be set to X'00'.

    void write_socks5_response()
    {
        auto self(shared_from_this());

        in_buf[0] = 0x05; in_buf[1] = 0x00; in_buf[2] = 0x00; in_buf[3] = 0x01;
        uint32_t realRemoteIP = out_socket.remote_endpoint().address().to_v4().to_ulong();
        uint16_t realRemoteport = htons(out_socket.remote_endpoint().port());

        std::memcpy(&in_buf[4], &realRemoteIP, 4);
        std::memcpy(&in_buf[8], &realRemoteport, 2);

        boost::asio::async_write(in_socket, boost::asio::buffer(in_buf, 10), // Всегда 10 байт согласно RFC1928
            [this, self](boost::system::error_code ec, std::size_t len)
            {
                if (!ec)
                {
                    do_read(3); // Читать оба сокета
                }
            });
    }


    void do_read(int direction)
    {
        auto self(shared_from_this());

        // Для того что бы разделить чтение по направлениям:
        if (direction & 0x1)
            in_socket.async_receive(boost::asio::buffer(in_buf),
                [this, self](boost::system::error_code ec, std::size_t len)
                {
                    if (!ec)
                    {
                        std::ostringstream what; what << "--> " << std::to_string(len) << " bytes";

                        do_write(1, len);
                    }
                    else //if (ec != boost::asio::error::eof)
                    {
                        // Скорее всего клиент закрыл, сокет => надо закрыть оба сокета и выйти из сессии
                        in_socket.close(); out_socket.close();
                    }

                });

        if (direction & 0x2)
            out_socket.async_receive(boost::asio::buffer(out_buf),
                [this, self](boost::system::error_code ec, std::size_t length)
                {
                    if (!ec)
                    {
                        std::ostringstream what; what << "<-- " << std::to_string(length) << " bytes";

                        do_write(2, length);
                    }
                    else //if (ec != boost::asio::error::eof)
                    {
                        // Скорее всего сервер закрыл, сокет => надо закрыть оба сокета и выйти из сессии
                        in_socket.close(); out_socket.close();
                    }
                });
    }

    void do_write(int direction, std::size_t Length)
    {
        auto self(shared_from_this());

        switch (direction)
        {
        case 1:
            boost::asio::async_write(out_socket, boost::asio::buffer(in_buf, Length),
                [this, self, direction](boost::system::error_code ec, std::size_t len)
                {
                    if (!ec)
                        do_read(direction);
                    else
                    {
                        // Скорее всего клиент закрыл, сокет => надо закрыть оба сокета и выйти из сессии
                        in_socket.close(); out_socket.close();
                    }
                });
            break;
        case 2:
            boost::asio::async_write(in_socket, boost::asio::buffer(out_buf, Length),
                [this, self, direction](boost::system::error_code ec, std::size_t len)
                {
                    if (!ec)
                        do_read(direction);
                    else
                    {
                        // Скорее всего Сервер закрыл, сокет => надо закрыть оба сокета и выйти из сессии
                        in_socket.close(); out_socket.close();
                    }
                });
            break;
        }
    }




    boost::asio::ip::tcp::socket in_socket;
    boost::asio::ip::tcp::socket out_socket;
    std::vector<char> in_buf;
    std::vector<char> out_buf;
    std::string remote_host;
    std::string remote_port;
    boost::asio::ip::tcp::resolver resolver;

};



class m_server
{
public:
    m_server(boost::asio::io_service& io_service, short port, uint buffer_size) : m_acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
        m_in_socket(io_service), m_buffer_size(buffer_size)
    {
        std::cout<< "m_server\n " << std::endl;
        make_accept();
    }

private:
    void make_accept()
    {
        m_acceptor.async_accept(m_in_socket,
        [this](boost::system::error_code ec)
        {
            if(!ec)
            {
                std::make_shared<m_session>(std::move(m_in_socket), m_buffer_size) -> start();
            }
            else
                std::cout << "ERROR accept socket" << std::endl;
                make_accept();
        }

    );
    }


    boost::asio::ip::tcp::acceptor m_acceptor;
    boost::asio::ip::tcp::socket m_in_socket;
    std::size_t m_buffer_size;

};




int main()
{
    boost::asio::io_service io_service;
    m_server server(io_service, 1080, 2048);
    io_service.run();


    std::cout << "Hello World!  1123" << std::endl;
    return 0;
}

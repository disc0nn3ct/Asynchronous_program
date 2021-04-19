#include <iostream>
#include "gen.hpp"
#include <boost/asio.hpp>


class m_session : public std::enable_shared_from_this<m_session>
{
public:
    m_session(boost::asio::ip::tcp::socket m_in_socket, uint m_buffer_size) : in_socket(std::move(m_in_socket)), out_socket(in_socket.get_executor().context()), in_buf(m_buffer_size), out_buf(m_buffer_size)
    {
    }
    void start()
    {
        read_handshake_sock5();
    }


private:
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



    }




    boost::asio::ip::tcp::socket in_socket;
    boost::asio::ip::tcp::socket out_socket;
    std::vector<char> in_buf;
    std::vector<char> out_buf;

};



class m_server
{
public:
    m_server(boost::asio::io_service& io_service, short port, uint buffer_size) : m_acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
        m_in_socket(io_service), m_buffer_size(buffer_size)
    {
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
//                std::make_shared<m_session>(std::move(m_in_socket), m_buffer_size) ->start;
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




    std::cout << "Hello World!" << std::endl;
    return 0;
}

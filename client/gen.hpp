#pragma once
#include <cstdint>
#include <memory>
#include <sys/socket.h>
#include <asm-generic/socket.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <iostream>

// Стандартные настройки
enum class SOCKS5_DEFAULTS : std::uint8_t{
    RSV		= 0x00,
    SUPPORT_AUTH	= 0x01,
    VERSION		= 0x05,
    VER_USERPASS	= 0x01
};


// DNS превратить в ip
enum class SOCKS5_RESOLVE{
    REMOTE_RESOLVE = 0x01,
    LOCAL_RESOLVE = 0x02
};

// Анонимный SOCKS5 соединеие (NOAUTH по умолчанию )
enum class SOCKS5_CGREETING_NOAUTH : std::uint8_t{
    VERSION		= static_cast<std::uint8_t>(SOCKS5_DEFAULTS::VERSION),
    NAUTH		= static_cast<std::uint8_t>(SOCKS5_DEFAULTS::SUPPORT_AUTH),
    AUTH		= static_cast<std::uint8_t>(0x00)
};

enum class SOCKS5_ADDR_TYPE : std::uint8_t{
    IPv4		= 0x01,
    DOMAIN		= 0x03,
    IPv6		= 0x04
};

// SOCKS5 клиент запрос подключения 
enum class SOCKS5_CCONNECTION_CMD : std::uint8_t{
    TCP_IP_STREAM	= 0x01,
    TCP_IP_PORT_BIND = 0x02,
    UDP_PORT	= 0x03
};

namespace SOCKS5{

inline static void NEG_CHECK(int value, const char* message){
    if(value < 0){
        std::perror(message);
        exit(EXIT_FAILURE);
    }
}

inline static int read_data(int net_file_des, char* buffer, int buff_read_len, int recv_flag){
    int recv_ret = recv(net_file_des, buffer, buff_read_len, recv_flag);
    NEG_CHECK(recv_ret, "recv()");
    return 0;
}

inline static int write_data(int net_file_des, const char* buffer, int buff_write_len, int send_flags){
    int send_ret = send(net_file_des, buffer, buff_write_len, send_flags);
    NEG_CHECK(send_ret, "send()");
    return 0;
}

inline static int close_connection(int net_fd){
    int close_ret = ::close(net_fd);
    NEG_CHECK(close_ret, "close()");
    return 0;
}

static inline int create_socket_client(const char* name, std::uint16_t port){
    hostent* hoste;
    sockaddr_in addr;
    if((hoste = gethostbyname(name)) == nullptr){
        herror("gethostbyname()");
        exit(EXIT_FAILURE);
    }

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    NEG_CHECK(sock_fd,"socket()");

    addr.sin_addr = *(reinterpret_cast<in_addr*>(hoste->h_addr));
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    memset(addr.sin_zero, 0, 8);
    int connect_ret = connect(sock_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(sockaddr));
    NEG_CHECK(connect_ret, "connect()");
    return sock_fd;
}
}




// Общий интерфейс
class SOCKS5_Handle{
	protected:
        virtual int connect_proxy_socks5(const std::string& server_ip, std::uint16_t server_port) = 0;
	public:
		virtual int read_proxy(std::size_t, char*) = 0;
		virtual int write_proxy(std::size_t, const char*) = 0;
        int connect_proxy_socks(const std::string& server_ip, std::uint16_t server_port){
            return this->connect_proxy_socks5(server_ip, server_port);
		}
		virtual ~SOCKS5_Handle() = default;
};

class SOCKS5_NOAUTH final : public SOCKS5_Handle{
	private:
		std::string _socks_serv_ip, _destination_addr;
		std::uint16_t _socks_serv_port, _destination_port;
		int _client_net_fd;
	public:
		SOCKS5_NOAUTH(const std::string& server_addr, std::uint16_t server_port);
		int read_proxy(std::size_t num_read, char* buffer) override;
		int write_proxy(std::size_t num_write, const char* buffer) override;
        int connect_proxy_socks5(const std::string& destination_addr, std::uint16_t destination_port) override;
		int client_greeting() const noexcept;
		int client_connection_request() noexcept;
		~SOCKS5_NOAUTH() override;
};


class SOCKS5_Common{
	public:
		static int remote_DNS_client_connection_request(int, const std::string&, const std::uint16_t&) noexcept;
		static int client_connection_request(int, const std::string&, const std::uint16_t&) noexcept;
};

class SOCKS5_Factory{
	public:
        enum class SOCKS5_Type : std::uint8_t{
            SOCKS5_NOAUTH
        };
		static std::unique_ptr<SOCKS5_Handle> CreateSocksClient(SOCKS5_Type type, 
				const std::string& server_addr, std::uint16_t server_port){
			switch(type){
                case SOCKS5_Type::SOCKS5_NOAUTH:
					return std::make_unique<SOCKS5_NOAUTH>(server_addr, server_port);
			}
			throw "Invalid SOCKS5 Proxy Type";
		}
};

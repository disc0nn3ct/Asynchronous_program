#include "gen.hpp"
#include <vector>
#include <arpa/inet.h>

// SOCKS5_ без авторизации
SOCKS5_NOAUTH::SOCKS5_NOAUTH(const std::string& serv_ip, std::uint16_t server_port)
	: _socks_serv_ip{serv_ip}, _socks_serv_port{server_port} {}

SOCKS5_NOAUTH::~SOCKS5_NOAUTH(){
	SOCKS5::close_connection(this->_client_net_fd);
}

int SOCKS5_NOAUTH::connect_proxy_socks5(const std::string& destination_addr, std::uint16_t destination_port){
		this->_destination_addr = destination_addr;		
		this->_destination_port = destination_port;

		int cli_sock_fd = SOCKS5::create_socket_client(this->_socks_serv_ip.c_str(),  this->_socks_serv_port);

		this->_client_net_fd = cli_sock_fd;
		this->client_greeting();
		SOCKS5_Common::remote_DNS_client_connection_request(this->_client_net_fd, this->_destination_addr, this->_destination_port);
		return cli_sock_fd;

}

int SOCKS5_NOAUTH::client_greeting() const noexcept {
	// [VERSION, NAUTH, AUTH]
	std::vector<char> client_greeting_msg = {
		static_cast<char>(SOCKS5_CGREETING_NOAUTH::VERSION),
		static_cast<char>(SOCKS5_CGREETING_NOAUTH::NAUTH),
		static_cast<char>(SOCKS5_CGREETING_NOAUTH::AUTH)
	}; 

    int write_ret = SOCKS5::write_data(this->_client_net_fd, client_greeting_msg.data(), client_greeting_msg.size(), 0);

	std::vector<char> server_choice(2);
    int read_ret = SOCKS5::read_data(this->_client_net_fd, server_choice.data(), server_choice.size(), 0);
	if(server_choice.at(0) == 0x05 && server_choice.at(1) == 0x00){
		return 0;
	}else{
		return -1;	
	}
	return 0;
}



int SOCKS5_NOAUTH::write_proxy(std::size_t num_write, const char* buffer){
	SOCKS5::write_data(this->_client_net_fd, buffer, num_write, 0);
	return 0;
}

int SOCKS5_NOAUTH::read_proxy(std::size_t num_read, char *buffer){
	SOCKS5::read_data(this->_client_net_fd, buffer, num_read, 0);
	return 0;
}



int SOCKS5_Common::client_connection_request(int net_serv_fd, const std::string& destination_addr, const std::uint16_t& destination_port) noexcept {
    // [VERSION, SOCKS_CMD, RESV(0x00), (SOCKS5 Addr Type)[TYPE, ADDR], DST_PORT]
    char ipv4_buffer[4];
    int inet_ret = inet_pton(AF_INET, destination_addr.c_str(), ipv4_buffer);

    std::vector<char> client_connection_request = {
        static_cast<char>(SOCKS5_CGREETING_NOAUTH::VERSION),
        static_cast<char>(SOCKS5_CCONNECTION_CMD::TCP_IP_STREAM),
        static_cast<char>(SOCKS5_DEFAULTS::RSV),
        static_cast<char>(SOCKS5_ADDR_TYPE::IPv4),
        static_cast<char>(ipv4_buffer[0]),
        static_cast<char>(ipv4_buffer[1]),
        static_cast<char>(ipv4_buffer[2]),
        static_cast<char>(ipv4_buffer[3]),
    };
    client_connection_request.push_back(static_cast<char>(destination_port>>8));
    client_connection_request.push_back(static_cast<char>(destination_port));

    int write_ret = SOCKS5::write_data(net_serv_fd, client_connection_request.data(), client_connection_request.size(), 0);

    constexpr std::size_t reply_bytes = 1 + 1 + 1 + 1 + (1 + 4) + 2;
    std::vector<char> server_responce(reply_bytes);
    int read_ret = SOCKS5::read_data(net_serv_fd, server_responce.data(), server_responce.size(), 0);
	
    if(server_responce.at(0) == 0x05 && server_responce.at(1) == 0x00){
        return 0;
    }else{
        return -1;
    }
}

int SOCKS5_Common::remote_DNS_client_connection_request(int client_net_fd, const std::string& destination_addr, const std::uint16_t& destination_port) noexcept {
	// [VERSION, SOCKS_CMD, RESV(0x00), (Addr Len, SOCKS5 DNS Addr Type)[len(Domain Name), 0x03, Domain Name], DST_PORT]

	std::vector<char> client_conn_request = {
		static_cast<char>(SOCKS5_CGREETING_NOAUTH::VERSION),
		static_cast<char>(SOCKS5_CCONNECTION_CMD::TCP_IP_STREAM),
		static_cast<char>(SOCKS5_DEFAULTS::RSV),
		static_cast<char>(SOCKS5_ADDR_TYPE::DOMAIN),
		static_cast<char>(destination_addr.size())
	};
	for(std::size_t i{}; i < destination_addr.length(); i++){
		client_conn_request.push_back(destination_addr.at(i));
	}
	client_conn_request.push_back(static_cast<char>(destination_port>>8));
	client_conn_request.push_back(static_cast<char>(destination_port));

	int write_ret = SOCKS5::write_data(client_net_fd, client_conn_request.data(), client_conn_request.size(), 0);

	std::vector<char> server_responce(client_conn_request.size());

	int read_ret = SOCKS5::read_data(client_net_fd, server_responce.data(), server_responce.size(), 0);
	
	if(server_responce.at(0) == 0x05 && server_responce.at(1) == 0x00){
		return 0;
	}else{
		return -1;
	}
}

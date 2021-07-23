#include <tipi/vault.hpp>
#include <iostream>

int main(int argc, char** argv) {

	auto base64_data_from_backend = "YWNjZXNzS2V5RGF0YQ==";
	auto user_input_password = "mysecret";
	tipi::vault v {
		tipi::vault_access_key{user_input_password}
	};

	for (tipi::auth_t& auth : v.auths()) {
		std::cout << "Authentication data for " << auth.user << ", password : " << auth.pass << std::endl;

		std::cout << " for Github Enterprise at : " << auth.endpoint
							  << std::endl;
	}

	return 0;
}
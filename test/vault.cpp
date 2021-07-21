#include <tipi/vault.hpp>
#include <iostream>

int main(int argc, char** argv) {

	auto base64_data_from_backend = "YWNjZXNzS2V5RGF0YQ==";
	auto user_input_password = "mysecret";
	tipi::vault v { base64_data_from_backend, user_input_password };

	for (tipi::auth_t& auth : v.auths()) {
		std::cout << "Authentication data for " << auth.auth_info.user << ", password : " << auth.auth_info.pass << std::endl;

		if (auth.endpoint) {
			std::cout << " for Github Enterprise at : " << *auth.endpoint
							  << std::endl;
		} else {
			std::cout << " for Github.com " << std::endl;
		}
	}

	return 0;
}
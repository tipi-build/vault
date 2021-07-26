#include <tipi/vault.hpp>
#include <iostream>

int main(int argc, char** argv) {

	std::cout << "Welcome to the tipi::vault test" << std::endl;
	auto user_input_password = "mysecret";
	tipi::vault_access_key the_black_keys {user_input_password};
	tipi::vault v {
		the_black_keys
	};

	v.add(tipi::auth_t {"user", "banana"});

	for (tipi::auth_t& auth : v.get_auths()) {
		std::cout << "Authentication data for " << auth.user << ", password : " << auth.pass << std::endl;

		std::cout << " for Github Enterprise at : " << auth.endpoint
							  << std::endl;
	}

	std::string buffer = v.get_encrypted_buffer();

	tipi::vault v_with_wrong_pass {
		tipi::vault_access_key{"yoursecret", the_black_keys.get_encrypted_buffer()},
		buffer
	};

	for (tipi::auth_t& auth : v_with_wrong_pass.get_auths()) {
		std::cout << "Authentication data for " << auth.user << ", password : " << auth.pass << std::endl;
		std::cout << " for Github Enterprise at : " << auth.endpoint << std::endl;
	}
	

	return 0;
}
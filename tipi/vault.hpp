#pragma once 

#include <iostream>
#include <map>
#include <gh/auth.hxx>
#include <pre/json/from_json.hpp>
#include <pre/json/to_json.hpp>

#include <tipi/detail/vault_impl.hpp>

namespace tipi {

  struct auth_t {
    gh::auth auth_info;

    //! gh enterprises url, if present it means the credentials are for use with an enterprise instance.
    std::optional<std::string> endpoint;
  };

  using auths_t = std::vector<auth_t>;

}

BOOST_FUSION_ADAPT_STRUCT(gh::auth, user, pass);
BOOST_FUSION_ADAPT_STRUCT(tipi::auth_t, auth_info, endpoint);

namespace tipi {

	/**
	 * 
	 */
	struct vault {

		//! Creates a default empty vault with the given vault key.
		vault(const std::string& vault_key) :
			vault_key_(vault_key),
			encrypted_buffer_("[]")
		{}

		//! Loads a vault with the given key from the provided encrypted_buffer.
		vault(const std::string& vault_key, const std::string& encrypted_buffer) :
			vault_key_(vault_key),
			encrypted_buffer_(encrypted_buffer)
		{}

		void add_auth(const std::string& user, const std::string& password/*, 
			const std::optional<std::string>& endpoint = std::nullopt*/ ) {
			//TODO: decrypt_vault(vault_key)
			std::cout << "Adding : " << user << " , " << password << std::endl;
			auto auths = pre::json::from_json<auths_t>(encrypted_buffer_);
			std::cout << "auths deserialized : " << auths.size() << std::endl;
			auths.push_back(auth_t{ gh::auth{user, password}, std::nullopt });
			std::cout << "auths size : " << auths.size() << std::endl;
			std::cout << pre::json::to_json(auths) << std::endl;
			//TODO: encrypt_vault(vault_key)
			encrypted_buffer_ = pre::json::to_json(auths);
		}

		auths_t auths() const {
			//TODO: decrypt_vault(vault_key)
			auto auths = pre::json::from_json<auths_t>(encrypted_buffer_);
			return auths;
		}

		std::string get_encrypted_buffer() const {
			return encrypted_buffer_;
		}

		void set_encrypted_buffer(const std::string& encrypted_buffer) {
			encrypted_buffer_ = encrypted_buffer;
		}

		////! Changes the vault_key and reencrypts the vault accordingly.
		//void vault_key(const std::string& new_vault_key) { 
		//	auto plain_vault = detail::decrypt_vault(vault_key_, encrypted_buffer_);

		//	vault_key_ = new_vault_key;

		//	encrypted_buffer_ = detail::encrypt_vault(vault_key_, plain_vault);
		//}

		//std::string vault_key() const { return vault_key_; }

		private: 
		std::string vault_key_;
		std::string encrypted_buffer_;
	};



}

#include <emscripten/bind.h>
#include <emscripten/val.h> 

	using namespace emscripten;
	EMSCRIPTEN_BINDINGS(tipi_vault) {
	  class_<tipi::vault>("tipi_vault")
	    .constructor<std::string>()
	    .constructor<std::string, std::string>()
	    .function("auths", &tipi::vault::auths)
	    .function("add_auth", &tipi::vault::add_auth)
	    .property("encrypted_buffer", &tipi::vault::get_encrypted_buffer, &tipi::vault::set_encrypted_buffer)
	    //.property("vault_key", &tipi::vault::vault_key, &tipi::vault::vault_key)
	    ;
}
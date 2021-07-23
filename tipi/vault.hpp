#pragma once 

#include <iostream>
#include <random>
#include <map>
#include <pre/json/from_json.hpp>
#include <pre/json/to_json.hpp>
#include <xxhr/util.hpp> // for base64
#include <boost/fusion/include/equal_to.hpp>

#include <emscripten/bind.h>
#include <emscripten/val.h> 


#include <tipi/detail/vault_impl.hpp>

namespace tipi {

  struct auth_t {
		std::string user;
		//! Personal access token or OAUTH token
		std::string pass;
    std::string endpoint;
  };
	using boost::fusion::operator==;

  using auths_t = std::vector<auth_t>;

	namespace {
		using namespace emscripten;
		EMSCRIPTEN_BINDINGS(auth_t) {
			value_object<tipi::auth_t>("auth_t")
				.field("user", &tipi::auth_t::user)
			  .field("pass", &tipi::auth_t::pass)
			  .field("endpoint", &tipi::auth_t::endpoint)
				;
		}			
	}
}

BOOST_FUSION_ADAPT_STRUCT(tipi::auth_t, user, pass, endpoint);

namespace tipi {
	/**
	 * \brief the vault is made up of multiple indirections this represents a passphrase  encrypted random generated access_key 
	 */ 
	struct vault_access_key {
		static constexpr std::size_t ACCESS_KEY_SIZE=64; 

		//! Generates a new random vault access key with hardware random dev
		vault_access_key(const std::string& passphrase) 
			: passphrase_(passphrase)
		{
				regenerate();
		}

		//! Load existing access key from buffer
		vault_access_key(const std::string& passphrase, const std::string& encrypted_buffer) 
			: passphrase_(passphrase),
				encrypted_buffer_(encrypted_buffer)
		{}

		//! regenerate the access key
		void regenerate() {
			std::random_device r;
			std::cout << "Generating with entropy : " << r.entropy() << std::endl;
			std::seed_seq seed{r(), r(), r(), r(), r(), r(), r(), r()}; 
	    std::mt19937 prng(seed);
			std::string access_key(ACCESS_KEY_SIZE, char{});
			std::generate(access_key.begin(), access_key.end() - 1, prng);
			std::cout << "Generated Access Key: " << access_key  << std::endl;
			//TODO: encrypt(passphrase, access_key);
			encrypted_buffer_ = xxhr::util::encode64(access_key);
		}

		std::string get_encrypted_buffer() const { return encrypted_buffer_; }
		void set_encrypted_buffer(const std::string& encrypted_buffer) { encrypted_buffer_ = encrypted_buffer; }

		std::string passphrase_;
		std::string encrypted_buffer_;

		private: 
		//! get the decrypted access key (needed by the vault
		std::string get() const {
			//TODO: decrypt(passphrase)
			auto decrypted_buffer = encrypted_buffer_;
			return decrypted_buffer;
		}

		friend class vault;
	};

	namespace {
		using namespace emscripten;
		EMSCRIPTEN_BINDINGS(vault_access_key) {
		  class_<vault_access_key>("vault_access_key")
		    .constructor<std::string>()
		    .constructor<std::string, std::string>()
		    .function("regenerate", &vault_access_key::regenerate)
		    .property("encrypted_buffer", &vault_access_key::get_encrypted_buffer, &tipi::vault_access_key::set_encrypted_buffer)
		    ;

		}
	}

	/**
	 * \brief vault to store access tokens and passwords to the different 
	 					source hosting services and more. 
	 */
	class vault {
		public:

		//! Creates a new empty vault with the given vault key.
		vault(const vault_access_key& vault_key) :
			vault_key_(vault_key),
			encrypted_buffer_(xxhr::util::encode64("[]"))
		{}

		//! Loads a vault with the given key from the provided encrypted_buffer.
		vault(const vault_access_key& vault_key, const std::string& encrypted_buffer) :
			vault_key_(vault_key),
			encrypted_buffer_(encrypted_buffer)
		{}

		void add(const auth_t& auth) {
			std::cout << "vault, using vault_key : " << vault_key_.get();
			//TODO: decrypt_vault(vault_key)
			auto auths = pre::json::from_json<auths_t>(xxhr::util::decode64(encrypted_buffer_));
			auths.push_back(auth);
			std::cout << pre::json::to_json(auths) << std::endl;
			//TODO: encrypt_vault(vault_key)
			encrypted_buffer_ = xxhr::util::encode64(pre::json::to_json(auths).dump());
		}

		void remove(const auth_t& auth) {
			//TODO: decrypt_vault(vault_key)
			auto auths = pre::json::from_json<auths_t>(xxhr::util::decode64(encrypted_buffer_));

			auto found = std::find(auths.begin(), auths.end(), auth);
			if (found != auths.end()) { auths.erase(found); }

			std::cout << "remove: " <<  pre::json::to_json(auths) << std::endl;
			encrypted_buffer_ = xxhr::util::encode64(pre::json::to_json(auths).dump());

		}

		auths_t auths() const {
			//TODO: decrypt_vault(vault_key)
			auto auths = pre::json::from_json<auths_t>(xxhr::util::decode64(encrypted_buffer_));
			return auths;
		}

		std::string get_encrypted_buffer() const { return encrypted_buffer_; }
		void set_encrypted_buffer(const std::string& encrypted_buffer) { encrypted_buffer_ = encrypted_buffer; }

		//! Changes the vault_key and reencrypts the vault accordingly.
		//void vault_key(const std::string& new_vault_key) { 
		//	auto plain_vault = detail::decrypt_vault(vault_key_, encrypted_buffer_);

		//	vault_key_ = new_vault_key;

		//	encrypted_buffer_ = detail::encrypt_vault(vault_key_, plain_vault);
		//}

		//std::string vault_key() const { return vault_key_; }

		private: 
		const vault_access_key& vault_key_;
		std::string encrypted_buffer_;
	};

	namespace {
		using namespace emscripten;
		EMSCRIPTEN_BINDINGS(tipi_vault) {
		  class_<vault>("tipi_vault")
		    .constructor<const vault_access_key&>()
		    .constructor<const vault_access_key&, std::string>()
		    .function("auths", &vault::auths)
		    .function("add", &vault::add)
		    .function("remove", &vault::remove)
		    .property("encrypted_buffer", &vault::get_encrypted_buffer, &vault::set_encrypted_buffer)
		    ;
		}
	}
}
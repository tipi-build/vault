#pragma once 

#include <gh/auth.hxx>
#include <pre/json/from_json.hpp>
#include <map>

#include <tipi/detail/vault_impl.hpp>

namespace tipi {

	using registered_users_t = std::map<std::string, bool>;

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
		vault(const std::string& vault_encrypted_buffer, const std::string& password) :
			vault_encrypted_buffer(vault_encrypted_buffer),
			password_(password)
		{}

		auths_t auths() const {
			//TODO: decrypt_vault(password)
			//TODO: deserizalize(vault)
			return { {.auth_info= gh::auth{"booom", "bar"}} };
		}

		std::string vault_encrypted_buffer;

		//! Changes the password and reencrypts the vault accordingly.
		void password(const std::string& new_password) { 
			auto plain_vault = detail::decrypt_vault(password_, vault_encrypted_buffer);

			password_ = new_password;

			vault_encrypted_buffer = detail::encrypt_vault(password_, plain_vault);
		}

		std::string password() const { return password_; }

		private: 
		std::string password_;
	};



}
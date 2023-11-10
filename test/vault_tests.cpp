#define BOOST_TEST_MODULE vault_tests
#include <boost/test/included/unit_test.hpp>

#include "wasm_boost_test.hpp"

#include <tipi/vault.hpp>
#include <iostream>

BOOST_AUTO_TEST_CASE(simple_use) {
	auto user_input_password = "mysecret";
	tipi::vault_access_key the_black_keys {user_input_password};
	tipi::vault v {
		the_black_keys
	};

	v.add(tipi::auth_t {"user", "banana", "https://mygithub.mycompany.org"});

  BOOST_REQUIRE(v.get_auths().size() == 1);
  BOOST_REQUIRE((v.get_auths()[0] == tipi::auth_t {"user", "banana", "https://mygithub.mycompany.org"}));

  v.remove(v.get_auths()[0]);

  BOOST_REQUIRE(v.get_auths().size() == 0);

	v.add(tipi::auth_t {"john", "cool", "https://mygithub.mycompany.org"});
	v.add(tipi::auth_t {"dam", "topito", "https://github.com"});

	for (tipi::auth_t& auth : v.get_auths()) {
		std::cout << "Authentication data for " << auth.user << ", password : " << auth.pass << std::endl;
		std::cout << " for Github at : " << auth.endpoint << std::endl;
	}

	std::string buffer = v.get_encrypted_buffer();

  BOOST_CHECK_THROW((
    tipi::vault {
        tipi::vault_access_key{user_input_password, "bluuuurrp"},
        buffer
    }.get_auths())
  , std::exception );

	tipi::vault vault_reloaded{the_black_keys, buffer};
  BOOST_REQUIRE(vault_reloaded.get_auths().size() == 2);
  BOOST_REQUIRE((vault_reloaded.get_auths() ==
      tipi::auths_t{
        tipi::auth_t {"john", "cool", "https://mygithub.mycompany.org"},
	      tipi::auth_t {"dam", "topito", "https://github.com"}
      })
  );
}


BOOST_AUTO_TEST_CASE(vault_for_gitlab) {
	auto user_input_password = "passwd";
	tipi::vault_access_key the_black_keys {user_input_password};
	tipi::vault v {
		the_black_keys
	};

	v.add(tipi::auth_t {"user", "appoo", "https://gitlab.self-hosted.com"});

  BOOST_REQUIRE(v.get_auths().size() == 1);
  BOOST_REQUIRE((v.get_auths()[0] == tipi::auth_t {"user", "appoo", "https://gitlab.self-hosted.com"}));

  v.remove(v.get_auths()[0]);

  BOOST_REQUIRE(v.get_auths().size() == 0);

	v.add(tipi::auth_t {"opo", "topi", "https://gitlab.self-hosted.com"});
	v.add(tipi::auth_t {"trik", "ico", "https://gitlab.com"});

	for (tipi::auth_t& auth : v.get_auths()) {
		std::cout << "Authentication data for " << auth.user << ", password : " << auth.pass << std::endl;
		std::cout << " for Gitlab at : " << auth.endpoint << std::endl;
	}

	std::string buffer = v.get_encrypted_buffer();

  BOOST_CHECK_THROW((
    tipi::vault {
        tipi::vault_access_key{user_input_password, "testmdpp"},
        buffer
    }.get_auths())
  , std::exception );

	tipi::vault vault_reloaded{the_black_keys, buffer};
  BOOST_REQUIRE(vault_reloaded.get_auths().size() == 2);
  BOOST_REQUIRE((vault_reloaded.get_auths() ==
      tipi::auths_t{
        tipi::auth_t {"opo", "topi", "https://gitlab.self-hosted.com"},
	      tipi::auth_t {"trik", "ico", "https://gitlab.com"}
      })
  );
}


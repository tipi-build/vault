#define BOOST_TEST_MODULE vault_access_key_tests
#include <boost/test/included/unit_test.hpp>

#include "wasm_boost_test.hpp"

#include <tipi/vault.hpp>

BOOST_AUTO_TEST_CASE(vault_access_key_gen) {
  std::random_device r;
  BOOST_CHECK(r.entropy() != 0);
  
  tipi::vault_access_key key("protected-by-this-passphrase");
  BOOST_REQUIRE(key.get_raw_key().size() == tipi::vault_access_key::ACCESS_KEY_SIZE); 

  BOOST_REQUIRE(!key.get_encrypted_buffer().empty());
}

BOOST_AUTO_TEST_CASE(change_passphrase) {
  
  tipi::vault_access_key key("protected-by-this-passphrase");
  auto rawkey = key.get_raw_key();
  std::cout << rawkey << std::endl;
  auto encrypted_buffer_before_passchange = key.get_encrypted_buffer();
  
  BOOST_REQUIRE(key.get_passphrase() == "protected-by-this-passphrase");
  key.set_passphrase("meh");

  BOOST_REQUIRE(key.get_passphrase() == "meh");
  BOOST_REQUIRE(key.get_raw_key() == rawkey);
  BOOST_REQUIRE(key.get_encrypted_buffer() != encrypted_buffer_before_passchange);
}

BOOST_AUTO_TEST_CASE(load_from_buffer) {

  tipi::vault_access_key key("protected-by-this-passphrase");
  auto rawkey = key.get_raw_key();
  const std::string encrypted_buffer = key.get_encrypted_buffer();

  {
    tipi::vault_access_key from_buffer { "protected-by-this-passphrase", encrypted_buffer };
    BOOST_REQUIRE(from_buffer.get_raw_key() == rawkey);
  }

  // test to deser with wrong pass
  {
    BOOST_CHECK_THROW( (tipi::vault_access_key { "protegeParCePass", encrypted_buffer }), std::exception);
  }

}

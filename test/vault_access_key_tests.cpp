#define BOOST_TEST_MODULE vault_access_key_tests
#include <boost/test/included/unit_test.hpp>

#include "wasm_boost_test.hpp"

#include <tipi/vault.hpp>
//#include <boost/random/random_device.hpp>

BOOST_AUTO_TEST_CASE(vault_access_key_gen) {
  //std::random_device r;
  //BOOST_CHECK(r.entropy() != 0);
  
  tipi::vault_access_key key("protected-by-this-passphrase");
  const size_t size_when_base64_encoded = ((4 * tipi::vault_access_key::ACCESS_KEY_SIZE / 3) + 3) & ~3;
  BOOST_REQUIRE(key.get_raw_key().size() == size_when_base64_encoded); 

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
    tipi::vault_access_key key_wrong_passphrase{ "protegeParCePass", encrypted_buffer };
    BOOST_CHECK_THROW( key_wrong_passphrase.get_raw_key(), std::exception);
  }

}


BOOST_AUTO_TEST_CASE(set_raw_key) {

  tipi::vault_access_key key("mypassphrase");
  for (size_t i=0; i < 1000; ++i) {
    std::cout << "Playing with a new rawkey" << std::endl;
    auto rawkey = key.get_raw_key();
    const std::string encrypted_buffer = key.get_encrypted_buffer();

    const auto new_rawkey = std::string("bananasplit!plus--") + std::to_string(i);
    std::cout << "new_rawkey size: " << new_rawkey.size() << " : " << new_rawkey << std::endl;
    key.set_raw_key(new_rawkey);
    BOOST_REQUIRE(key.get_encrypted_buffer() != encrypted_buffer);
    BOOST_REQUIRE(key.get_raw_key() == new_rawkey);
  }

}

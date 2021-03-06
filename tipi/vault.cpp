#include <tipi/vault.hpp>

#ifdef __EMSCRIPTEN__
  #include <emscripten/bind.h>
  #include <emscripten/val.h> 
#endif

#ifdef __EMSCRIPTEN__



  namespace tipi {
    namespace {
    using namespace emscripten;

    std::string get_exception_message(intptr_t exceptionPtr) {
      return std::string(reinterpret_cast<std::exception *>(exceptionPtr)->what());
    }

    EMSCRIPTEN_BINDINGS(vault_bindings) {
      emscripten::function("get_exception_message", &get_exception_message);

      enum_<endpoint_t>("endpoint_t")
          .value("GITHUB", endpoint_t::GITHUB)
          .value("TIPI_STORAGE", endpoint_t::TIPI_STORAGE)
      ;

      value_object<tipi::auth_t>("auth_t")
        .field("user", &tipi::auth_t::user)
        .field("pass", &tipi::auth_t::pass)
        .field("endpoint", &tipi::auth_t::endpoint)
        .field("type", &tipi::auth_t::type)
        ;
      register_vector<tipi::auth_t>("vector_auth_t");

      class_<vault_access_key>("vault_access_key")
        .constructor<std::string>()
        .constructor<std::string, std::string>()
        .function("regenerate", &vault_access_key::regenerate)
        .property("encrypted_buffer", &vault_access_key::get_encrypted_buffer, &vault_access_key::set_encrypted_buffer)
        .property("passphrase", &vault_access_key::get_passphrase, &vault_access_key::set_passphrase)
        .property("raw_key", &vault_access_key::get_raw_key,  &vault_access_key::set_raw_key)
        ;

      class_<vault>("tipi_vault")
        .constructor<const vault_access_key&>()
        .constructor<const vault_access_key&, std::string>()
        .function("add", &vault::add)
        .function("remove", &vault::remove)
        .property("auths", &vault::get_auths, &vault::set_auths)
        .property("encrypted_buffer", &vault::get_encrypted_buffer, &vault::set_encrypted_buffer)
        ;
    }
    }
  }
#endif

namespace tipi {
  //! Creates a new empty vault with the given vault key.
  vault::vault(const vault_access_key& access_key) :
    access_key_(access_key)
  {
    auths_t auths{};
    set_auths(auths);
  }

  //! Loads a vault with the given key from the provided encrypted_buffer.
  vault::vault(const vault_access_key& access_key, const std::string& encrypted_buffer) :
    access_key_(access_key),
    encrypted_buffer_(encrypted_buffer)
  {}

  void vault::add(const auth_t& auth) {
    auto auths = get_auths();
    auths.push_back(auth);
    set_auths(auths);
  }

  void vault::remove(const auth_t& auth) {
    auto auths = get_auths();

    auto found = std::find(auths.begin(), auths.end(), auth);
    if (found != auths.end()) { auths.erase(found); }
    set_auths(auths);
  }

  auths_t vault::get_auths() const {
    return pre::json::from_json<auths_t>(detail::decrypt(access_key_.get_raw_key(), encrypted_buffer_));
  }

  void vault::set_auths(const auths_t& auths) {
    encrypted_buffer_ = detail::encrypt(access_key_.get_raw_key(), pre::json::to_json(auths).dump() );

  }

  std::string vault::get_encrypted_buffer() const { return encrypted_buffer_; }
  void vault::set_encrypted_buffer(const std::string& encrypted_buffer) { encrypted_buffer_ = encrypted_buffer; }

  //! Changes the vault_access_key and reencrypts the vault accordingly.
  void vault::access_key(const vault_access_key& new_vault_access_key) { 
    auto auths = get_auths();
    access_key_ = new_vault_access_key;
    set_auths(auths);
  }

  vault_access_key vault::access_key() const { return access_key_; }
}


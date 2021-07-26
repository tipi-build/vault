#pragma once 

#include <iostream>
#include <random>
#include <map>
#include <pre/json/from_json.hpp>
#include <pre/json/to_json.hpp>
#include <xxhr/util.hpp> // for base64
#include <boost/fusion/include/equal_to.hpp>

#ifdef __EMSCRIPTEN__
  #include <emscripten/bind.h>
  #include <emscripten/val.h> 
#endif


#include <tipi/detail/vault_impl.hpp>

namespace tipi {

  enum class endpoint_t {
    GITHUB
  };

  struct auth_t {
    std::string user;
    //! Personal access token or OAUTH token
    std::string pass;
    std::string endpoint;
    endpoint_t type;
  };
  using boost::fusion::operator==;

  using auths_t = std::vector<auth_t>;

#ifdef __EMSCRIPTEN__
  namespace {
    using namespace emscripten;
    EMSCRIPTEN_BINDINGS(auth_t) {
      value_object<tipi::auth_t>("auth_t")
        .field("user", &tipi::auth_t::user)
        .field("pass", &tipi::auth_t::pass)
        .field("endpoint", &tipi::auth_t::endpoint)
        .field("type", &tipi::auth_t::type)
        ;

      enum_<endpoint_t>("endpoint_t")
          .value("GITHUB", endpoint_t::GITHUB)
      ;
    }	
  }
#endif
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
      encrypted_buffer_ = xxhr::util::encode64(detail::encrypt(passphrase_, access_key));
    }

    std::string get_encrypted_buffer() const { return encrypted_buffer_; }
    void set_encrypted_buffer(const std::string& encrypted_buffer) { encrypted_buffer_ = encrypted_buffer; }

    std::string passphrase_;
    std::string encrypted_buffer_;

    private: 
    //! get the decrypted access key (needed by the vault to actually read it's content)
    std::string get() const {
      auto decrypted_access_key = xxhr::util::decode64(detail::decrypt(passphrase_, encrypted_buffer_));
      return decrypted_access_key;
    }

    friend class vault;
  };

#ifdef __EMSCRIPTEN__
  namespace {
    using namespace emscripten;
    EMSCRIPTEN_BINDINGS(vault_access_key) {
      class_<vault_access_key>("vault_access_key")
        .constructor<std::string>()
        .constructor<std::string, std::string>()
        .function("regenerate", &vault_access_key::regenerate)
        .property("encrypted_buffer", &vault_access_key::get_encrypted_buffer, &vault_access_key::set_encrypted_buffer)
        ;

    }
  }
#endif

  /**
   * \brief vault to store access tokens and passwords to the different 
             source hosting services and more. 
   */
  class vault {
    public:

    //! Creates a new empty vault with the given vault key.
    vault(const vault_access_key& access_key) :
      access_key_(access_key)
    {
      auths_t auths{};
      set_auths(auths);
    }

    //! Loads a vault with the given key from the provided encrypted_buffer.
    vault(const vault_access_key& access_key, const std::string& encrypted_buffer) :
      access_key_(access_key),
      encrypted_buffer_(encrypted_buffer)
    {}

    void add(const auth_t& auth) {
      auto auths = get_auths();
      auths.push_back(auth);
      std::cout << pre::json::to_json(auths) << std::endl;
      set_auths(auths);
    }

    void remove(const auth_t& auth) {
      auto auths = get_auths();

      auto found = std::find(auths.begin(), auths.end(), auth);
      if (found != auths.end()) { auths.erase(found); }

      std::cout << "remove: " <<  pre::json::to_json(auths) << std::endl;

      set_auths(auths);
    }

    auths_t get_auths() const {
      return pre::json::from_json<auths_t>(detail::decrypt(access_key_.get(), encrypted_buffer_));
    }

    void set_auths(const auths_t& auths) {
      encrypted_buffer_ = detail::encrypt(access_key_.get(), pre::json::to_json(auths).dump());
    }

    std::string get_encrypted_buffer() const { return encrypted_buffer_; }
    void set_encrypted_buffer(const std::string& encrypted_buffer) { encrypted_buffer_ = encrypted_buffer; }

    //! Changes the vault_access_key and reencrypts the vault accordingly.
    void access_key(const vault_access_key& new_vault_access_key) { 
      auto auths = get_auths();
      access_key_ = new_vault_access_key;
      set_auths(auths);
    }

    vault_access_key access_key() const { return access_key_; }

    private: 

    vault_access_key access_key_;
    std::string encrypted_buffer_;
  };

#ifdef __EMSCRIPTEN__
  namespace {
    using namespace emscripten;
    EMSCRIPTEN_BINDINGS(tipi_vault) {
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
#endif
}
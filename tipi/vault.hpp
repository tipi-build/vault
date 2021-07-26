#pragma once 

#include <iostream>
#include <random>
#include <map>
#include <pre/json/from_json.hpp>
#include <pre/json/to_json.hpp>
#include <xxhr/util.hpp> // for base64
#include <boost/fusion/include/equal_to.hpp>


#include <tipi/detail/encryption.hpp>

namespace tipi {

  enum class endpoint_t {
    GITHUB
  };

  struct auth_t {
    std::string user;
    //! Personal access token or OAUTH token
    std::string pass;
    std::string endpoint;
    endpoint_t type{};
  };
  using boost::fusion::operator==;

  using auths_t = std::vector<auth_t>;
}

BOOST_FUSION_ADAPT_STRUCT(tipi::auth_t, user, pass, endpoint, type);

namespace tipi {

  /**
   * \brief This represents a passphrase  encrypted random generated access_key for the vault
   *        Thanks to this indirection a vault can be shared throughout an organization. 
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
      encrypted_buffer_ = detail::encrypt(passphrase_, access_key);
    }

    std::string get_encrypted_buffer() const { return encrypted_buffer_; }
    void set_encrypted_buffer(const std::string& encrypted_buffer) { encrypted_buffer_ = encrypted_buffer; }

    //! \brief get the decrypted access key (needed by the vault to actually read it's content)
    std::string get() const {
      auto decrypted_access_key = detail::decrypt(passphrase_, encrypted_buffer_);
      return decrypted_access_key;
    }

    //! \brief set the decrypted access key from an external plain text value
    void set(const std::string& plain_access_key) {
      encrypted_buffer_ = detail::encrypt(passphrase_, plain_access_key);

    }

    std::string passphrase_;
    std::string encrypted_buffer_;
  };



  /**
   * \brief vault to store access tokens and passwords to the different 
   *         source hosting services and more. All operations happens on
   *         the encrypted vault and decrypts + edit + reencrypts it.
   */
  class vault {
    public:

    //! Creates a new empty vault with the given vault key.
    vault(const vault_access_key& access_key);

    //! \brief Loads a vault with the given key from the provided encrypted_buffer.
    vault(const vault_access_key& access_key, const std::string& encrypted_buffer);

    //! \brief Adds the provided auth to the vault
    void add(const auth_t& auth);

    //! \brief remove the provide auth from the vault
    void remove(const auth_t& auth);

    //! \return all auths stored in the vault
    auths_t get_auths() const;

    //! \param auths replaces all auths stored in the vault
    void set_auths(const auths_t& auths);

    std::string get_encrypted_buffer() const;
    void set_encrypted_buffer(const std::string& encrypted_buffer);

    //! Changes the vault_access_key and reencrypts the vault accordingly.
    void access_key(const vault_access_key& new_vault_access_key);

    vault_access_key access_key() const;

    private: 
    vault_access_key access_key_;
    std::string encrypted_buffer_;
  };


}



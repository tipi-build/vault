#pragma once 

#include <random>
#include <map>
#include <pre/json/from_json.hpp>
#include <pre/json/to_json.hpp>
#include <boost/fusion/include/equal_to.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>


#include <tipi/detail/encryption.hpp>

namespace tipi {

  enum class endpoint_t {
    GITHUB,
    GITLAB,
    GIT,
    TIPI_STORAGE
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
      std::seed_seq seed{r(), r(), r(), r(), r(), r(), r(), r()}; 
      std::mt19937 prng(seed);
      std::string access_key(ACCESS_KEY_SIZE, char{});
      std::generate(access_key.begin(), access_key.end() - 1, prng);
      auto random_key = encode64(access_key);
      set_raw_key(random_key);
    }


    //! \return your most precious secret
    std::string get_passphrase() const {
      return passphrase_;
    }

    //! \brief reencode the access key storage with a new passphrase
    void set_passphrase(const std::string& new_passphrase) {
      auto decrypted_access_key = get_raw_key();
      passphrase_ = new_passphrase;
      set_raw_key(decrypted_access_key);
    } 

    //! \brief get the decrypted access key (needed by the vault to actually read it's content)
    std::string get_raw_key() const {
      auto decrypted_access_key = detail::decrypt(passphrase_, encrypted_buffer_);
      return decrypted_access_key;
    }

    //! \brief set the decrypted access key from an external plain text value
    void set_raw_key(const std::string& plain_access_key) {
      encrypted_buffer_ = detail::encrypt(passphrase_, plain_access_key);
    }

    //! \return base64 encoded encrypted buffer
    std::string get_encrypted_buffer() const { return encrypted_buffer_; }
    void set_encrypted_buffer(const std::string& encrypted_buffer) { encrypted_buffer_ = encrypted_buffer; }

    private:
    std::string passphrase_;
    std::string encrypted_buffer_;
  };


    std::string decode64(const std::string &val) {
      using namespace boost::archive::iterators;
      using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
      // See https://svn.boost.org/trac10/ticket/5629#comment:9
      // Boost binary_from_base64 transforms '=' into '\0', they need to be removed to support binary data
      auto padding_count = std::count(val.end() - std::min(std::size_t{2}, val.size()), val.end() , '=');
      return std::string(It(std::begin(val)), It(std::end(val) - padding_count));
    }


    std::string encode64(const std::string &val) {
      using namespace boost::archive::iterators;
      using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
      auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
      return tmp.append((3 - val.size() % 3) % 3, '=');
    }



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



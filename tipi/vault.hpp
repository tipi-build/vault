#pragma once 

#include <random>
#include <map>
#include <pre/json/from_json.hpp>
#include <pre/json/to_json.hpp>
#include <xxhr/util.hpp> // for base64
#include <boost/fusion/include/equal_to.hpp>

#include <tipi/detail/sha1.hpp>
#include <tipi/detail/encryption.hpp>

namespace tipi {

  enum class endpoint_t {
    GITHUB,
    TIPI_STORAGE,
    TIPI_VAULT_PPK
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

  struct auth_patch_t {
    std::string patch_hash;
    std::string parent_hash;
    std::string patch;
  };

  struct vault_info_t {
    std::string public_key;
    std::string revision;
  };

  struct access_key_info_t {
    size_t revision;
  };

  struct deserialized_vault_data_t {
    auths_t auths;
    vault_info_t vault_info;
  };
}

BOOST_FUSION_ADAPT_STRUCT(tipi::auth_t, user, pass, endpoint, type);
BOOST_FUSION_ADAPT_STRUCT(tipi::auth_patch_t, patch_hash, parent_hash, patch);
BOOST_FUSION_ADAPT_STRUCT(tipi::vault_info_t, public_key, revision);
BOOST_FUSION_ADAPT_STRUCT(tipi::access_key_info_t, revision);

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
      auto random_key = xxhr::util::encode64(access_key);
      set_raw_key(random_key);
    }

    bool update() {
      if(encrypted_buffer_.rfind(detail::v2vault_preamble, 0) == 0) {
        return false; /* already at v2 */
      }
      else {
        // reencrypting the same raw key does the trick...
        set_raw_key(get_raw_key());
        return true;
      }
    }

    access_key_info_t get_info() {
      auto decryption_result = detail::decrypt(passphrase_, encrypted_buffer_);

      if(decryption_result.authenticated_data.empty()) {
        return access_key_info_t{ .revision = 0 };
      }
      
      return pre::json::from_json<access_key_info_t>(decryption_result.authenticated_data);
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
      auto decryption_result = detail::decrypt(passphrase_, encrypted_buffer_);
      return decryption_result.plain_text;
    }

    //! \brief set the decrypted access key from an external plain text value
    void set_raw_key(const std::string& plain_access_key) {
      access_key_info_t info = get_info();
      info.revision++;

      std::string info_json = pre::json::to_json(info).dump();
      encrypted_buffer_ = detail::encrypt(passphrase_, plain_access_key, info_json);
    }

    //! \return base64 encoded encrypted buffer
    std::string get_encrypted_buffer() const { return encrypted_buffer_; }
    void set_encrypted_buffer(const std::string& encrypted_buffer) { encrypted_buffer_ = encrypted_buffer; }

    private:
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

    //! \param patch the auth_patch_t to apply to this vault
    bool apply_patch(const auth_patch_t& patch);

    //! \param auth the auth_t to generate a patch from (against this vault revision)
    auth_patch_t create_patch(const auth_t& auth);

    //! \brief retrieves the vault info
    vault_info_t get_info(bool verify_sig = false);

    std::string get_encrypted_buffer() const;
    void set_encrypted_buffer(const std::string& encrypted_buffer);

    //! Changes the vault_access_key and reencrypts the vault accordingly.
    void access_key(const vault_access_key& new_vault_access_key);

    //! \brief updates the vault to the required version. If the methods returns true 
    // the vault should be saved to the server
    bool update();

    vault_access_key access_key() const;

    private: 

    //! \brief pack a new ECIES keypair into an auth_t
    inline auth_t generate_ecies_keypair_auth() {
      detail::ecies_keypair new_keypair = detail::generate_ecies_keypair();
      auth_t result;

      result.endpoint = "tipi-ecies";
      result.user = new_keypair.public_key;
      result.pass = new_keypair.private_key;
      result.type = endpoint_t::TIPI_VAULT_PPK;

      return result;
    }

    inline detail::ecies_keypair extract_ecies_keypair_from_auth(const auth_t& auth) {

      if(auth.type != endpoint_t::TIPI_VAULT_PPK) {
        throw std::runtime_error("Vault type was not <TIPI_VAULT_PPK>");
      }

      detail::ecies_keypair result;
      result.private_key = auth.pass;
      result.public_key = auth.user;

      return result;
    }

    deserialized_vault_data_t decrypt_and_deserialize_vault() const;

    void save_vault_internal(const auths_t& auths, vault_info_t vault_info, const bool updated_hash = true);

    vault_access_key access_key_;
    std::string encrypted_buffer_;
  };


}



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
          .value("TIPI_VAULT_PPK", endpoint_t::TIPI_VAULT_PPK)
      ;

      value_object<tipi::auth_t>("auth_t")
        .field("user", &tipi::auth_t::user)
        .field("pass", &tipi::auth_t::pass)
        .field("endpoint", &tipi::auth_t::endpoint)
        .field("type", &tipi::auth_t::type)
        ;
      register_vector<tipi::auth_t>("vector_auth_t");

      value_object<tipi::auth_patch_t>("auth_patch_t")
        .field("patch_hash", &tipi::auth_patch_t::patch_hash)
        .field("parent_hash", &tipi::auth_patch_t::parent_hash)
        .field("auth_entry", &tipi::auth_patch_t::encrypted_patch)
        ;

      value_object<tipi::vault_info_t>("vault_info_t")
        .field("public_key", &tipi::vault_info_t::public_key)
        .field("revision", &tipi::vault_info_t::revision)
        ;

      value_object<tipi::access_key_info_t>("access_key_info_t")
        .field("revision", &tipi::access_key_info_t::revision)
        ;

      class_<vault_access_key>("vault_access_key")
        .constructor<std::string>()
        .constructor<std::string, std::string>()
        .function("regenerate", &vault_access_key::regenerate)
        .function("update", &vault_access_key::update)
        .function("get_info", &vault_access_key::get_info)
        .property("encrypted_buffer", &vault_access_key::get_encrypted_buffer, &vault_access_key::set_encrypted_buffer)
        .property("passphrase", &vault_access_key::get_passphrase, &vault_access_key::set_passphrase)
        .property("raw_key", &vault_access_key::get_raw_key,  &vault_access_key::set_raw_key)
        ;

      class_<vault>("tipi_vault")
        .constructor<const vault_access_key&>()
        .constructor<const vault_access_key&, std::string>()
        .function("add", &vault::add)
        .function("remove", &vault::remove)
        .function("apply_patch", &vault::apply_patch)
        .function("create_patch", &vault::create_patch)
        .function("get_info", &vault::get_info)
        .function("update", &vault::update)
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
    vault_info_t vault_info{};

    save_vault_internal(auths, vault_info);
    update();
  }

  //! Loads a vault with the given key from the provided encrypted_buffer.
  vault::vault(const vault_access_key& access_key, const std::string& encrypted_buffer) :
    access_key_(access_key),
    encrypted_buffer_(encrypted_buffer)
  {}

  void vault::add(const auth_t& auth) {
    deserialized_vault_data_t dv = decrypt_and_deserialize_vault();
    dv.auths.push_back(auth);
    save_vault_internal(dv.auths, dv.vault_info);
  }

  void vault::remove(const auth_t& auth) {
    deserialized_vault_data_t dv = decrypt_and_deserialize_vault();

    auto found = std::find(dv.auths.begin(), dv.auths.end(), auth);
    if (found != dv.auths.end()) { dv.auths.erase(found); }
    
    save_vault_internal(dv.auths, dv.vault_info);
  }

  auths_t vault::get_auths() const {
    deserialized_vault_data_t dv = decrypt_and_deserialize_vault();
    return dv.auths;
  }

  void vault::set_auths(const auths_t& auths) {
    deserialized_vault_data_t dv = decrypt_and_deserialize_vault();
    save_vault_internal(auths, dv.vault_info);
  }

  bool vault::apply_patch(const auth_patch_t& patch) {
    auto decr_result = detail::decrypt(access_key_.get_raw_key(), encrypted_buffer_);

    auths_t auths = pre::json::from_json<auths_t>(decr_result.plain_text);
    vault_info_t vault_info;
    auth_t ppk_entry;

    // get the first (*sic*) ppk vault entry
      auto vault_ppk_enty = std::find_if(auths.begin(), auths.end(), 
        [](auth_t a){ return a.type == tipi::endpoint_t::TIPI_VAULT_PPK; }); 

    // OH NO! we don't have a public/private key set
    if(vault_ppk_enty == auths.end()) {     
      ppk_entry = generate_ecies_keypair_auth();
      auths.push_back(ppk_entry);   
    }
    else {
      ppk_entry = *vault_ppk_enty;
    }

    if(decr_result.is_legacy_vault) {
      vault_info.public_key = ppk_entry.user; // "user" is the public key...
      vault_info.revision = "";
    }
    else {
      vault_info = pre::json::from_json<vault_info_t>(decr_result.authenticated_data);
    }

    if(vault_info.revision == patch.patch_hash) {
      return true;  // already applied - done.
    }

    // decrypt and deserialize the patch
    std::string patch_ct = detail::decrypt_ecies_message(patch.encrypted_patch, ppk_entry.pass);
    auth_t patch_auth = pre::json::from_json<auth_t>(patch_ct);

    // check if it can be applied & apply if so
    if(patch.parent_hash == vault_info.revision) {
      
      // remove existing on with the same endpoint
      auto existing_auth_itt = std::find_if(auths.begin(), auths.end(), 
        [&](auth_t a){ return a.endpoint == patch_auth.endpoint; }); 

      if(existing_auth_itt != auths.end()) {
        auths.erase(existing_auth_itt);
      }

      // finally add the new one, update vault info and save
      auths.push_back(patch_auth);
      vault_info.revision = patch.patch_hash;

      save_vault_internal(auths, vault_info, false);  // don't re-calc the hash to not loose subsequent updates in a sequence
      return true;
    }

    return false;
  }
  
  void vault::save_vault_internal(const auths_t& auths, vault_info_t vault_info, const bool updated_hash) {
    std::string key = access_key_.get_raw_key();
    std::string auths_json = pre::json::to_json(auths).dump();

    if(updated_hash || vault_info.revision.empty())
      vault_info.revision = sha1::to_string(sha1::hash(auths_json));

    std::string aad_json = pre::json::to_json(vault_info).dump();

    encrypted_buffer_ = detail::encrypt(key, auths_json, aad_json);
  }

  vault_info_t vault::get_info(bool verify_sig) {
    std::string aad;

    if(verify_sig) {
      auto decr_result = detail::decrypt(access_key_.get_raw_key(), encrypted_buffer_);
      aad = decr_result.authenticated_data;
    }
    else {
      aad = detail::get_aad_part(encrypted_buffer_);
    }

    return pre::json::from_json<vault_info_t>(aad);
  }

  bool vault::update() {
    bool was_updated = false; 
    auto decr_result = detail::decrypt(access_key_.get_raw_key(), encrypted_buffer_);

    auths_t auths = pre::json::from_json<auths_t>(decr_result.plain_text);
    vault_info_t vault_info;
    auth_t ppk_entry;

    // get the first (*sic*) ppk vault entry
    auto vault_ppk_enty = std::find_if(auths.begin(), auths.end(), 
        [](auth_t a){ return a.type == tipi::endpoint_t::TIPI_VAULT_PPK; }); 

    // OH NO! we don't have a public/private key set
    if(vault_ppk_enty == auths.end()) {   
      ppk_entry = generate_ecies_keypair_auth();
      auths.push_back(ppk_entry);   
      was_updated = true;
    }

    if(decr_result.is_legacy_vault == true) {      
      vault_info.public_key = ppk_entry.user; // TIPI_VAULT_PPK."user" is the public key...
      vault_info.revision = "";
      was_updated = true;
    }

    if(was_updated) {
      save_vault_internal(auths, vault_info);
    }

    return was_updated;
  }

  auth_patch_t vault::create_patch(const auth_t& auth) {
    vault_info_t info = get_info();
    
    std::string patch_cleartext_json = pre::json::to_json(auth).dump();
    std::string patch_hash = sha1::to_string(sha1::hash(info.revision + patch_cleartext_json));
    auth_patch_t patch{};
    patch.parent_hash = info.revision;
    patch.patch_hash = patch_hash;
    patch.encrypted_patch = detail::encrypt_ecies_message(patch_cleartext_json, info.public_key);

    return patch;
  }

  deserialized_vault_data_t vault::decrypt_and_deserialize_vault() const {
    auto decr_result = detail::decrypt(access_key_.get_raw_key(), encrypted_buffer_);

    deserialized_vault_data_t result;
    result.auths = pre::json::from_json<auths_t>(decr_result.plain_text);
    result.vault_info =  pre::json::from_json<vault_info_t>(decr_result.authenticated_data);

    return result;
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


#pragma once

#include <string>
#include <cstdint>

#include <cryptopp/default.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/chachapoly.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/donna.h>
#include <cryptopp/hex.h>

#include <xxhr/util.hpp> // for base64

#include "../vault.hpp"

namespace tipi::detail {

using CryptoPP::DefaultEncryptorWithMAC;
using CryptoPP::DefaultDecryptorWithMAC;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::FileSource;
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

using CryptoPP::AES;
using CryptoPP::SHA256;
using CryptoPP::HMAC;
using CryptoPP::DataParametersInfo;
using CryptoPP::DataEncryptorWithMAC;
using CryptoPP::DataDecryptorWithMAC;
using CryptoPP::SimpleProxyFilter;
using CryptoPP::XChaCha20Poly1305;
using CryptoPP::HKDF;
using CryptoPP::ECIES;
using CryptoPP::ECP;
using CryptoPP::Name::Pad;
using CryptoPP::Name::InsertLineBreaks;


const size_t SALT_SIZE = 8;
const size_t ITERATIONS = 2500;
using DataEncryptorTipiVault = DataEncryptorWithMAC <
	AES,SHA256,
	HMAC<SHA256>,
	DataParametersInfo<
		AES::BLOCKSIZE, AES::DEFAULT_KEYLENGTH, HMAC<SHA256>::DIGESTSIZE, SALT_SIZE, ITERATIONS 
	>>;

using Vault_v1_DataDecryptorWithMAC = DataDecryptorWithMAC <
	AES,SHA256,
	HMAC<SHA256>,
	DataParametersInfo<
		AES::BLOCKSIZE, AES::DEFAULT_KEYLENGTH, HMAC<SHA256>::DIGESTSIZE, SALT_SIZE, ITERATIONS 
	>>;

	struct AEAD_decryption_result {
		std::string plain_text;
		std::string authenticated_data;
		bool is_legacy_vault;
	};

	struct ecies_keypair {
		std::string private_key;
		std::string public_key;
	};

	const std::string v2vault_preamble = "v2:";
	const std::string v2vault_separator = ":";

	inline std::string encrypt(const std::string& password_str, const std::string& plain_buffer, const std::string& additional_authenticated_data) {
		// init the PRNG
		std::random_device r;
		std::seed_seq seed{r(), r(), r(), r(), r(), r(), r(), r()}; 
		std::mt19937 prng(seed);

		// encrypt the data using cryptopp's xchachapoly implementation
		XChaCha20Poly1305::Encryption encryption_engine;

		// create a nonce
		std::string nonce_str(encryption_engine.IVSize(), char{});
		std::generate(nonce_str.begin(), nonce_str.end() - 1, prng);
		const uint8_t* nonce = reinterpret_cast<const uint8_t*>(nonce_str.c_str());

		// derive the key from the password using HKDF 
		const uint8_t* password = reinterpret_cast<const uint8_t*>(password_str.c_str());

		uint8_t* key{ new uint8_t[encryption_engine.DefaultKeyLength()]{} };
		HKDF<SHA256> hkdf;
		hkdf.DeriveKey(key, encryption_engine.DefaultKeyLength(), 
			password, password_str.length(), 
			nonce, nonce_str.length(),
			NULL, 0
		);

		// encrypt everything
		const uint8_t* plain_text = reinterpret_cast<const uint8_t*>(plain_buffer.c_str());
		const uint8_t* aad = reinterpret_cast<const uint8_t*>(additional_authenticated_data.c_str());		
		uint8_t* cyphertext{ new uint8_t[plain_buffer.length()]{} };
		uint8_t* mac{ new uint8_t[encryption_engine.DigestSize()]{} };

		encryption_engine.SetKeyWithIV(key, encryption_engine.DefaultKeyLength(), nonce, encryption_engine.IVSize());
		encryption_engine.EncryptAndAuthenticate(cyphertext, 
			mac, encryption_engine.DigestSize(), 
			nonce, encryption_engine.IVSize(), 
			aad, additional_authenticated_data.length(), 
			plain_text, plain_buffer.length());
		

		std::string ct_str = std::string(reinterpret_cast<char const*>(cyphertext), plain_buffer.length());
		std::string mac_str = std::string(reinterpret_cast<char const*>(mac), encryption_engine.DigestSize());

		// v2 vault is formated like:
		// v2:<nonce>:<BASE64 encoded XChaCha20-Poly1305 encrypted message>:<MAC>:<base64 encoded AAD (additional authenticated data)>
		std::string encrypted = v2vault_preamble + xxhr::util::encode64(nonce_str) 
			+ v2vault_separator + xxhr::util::encode64(ct_str)
			+ v2vault_separator + xxhr::util::encode64(mac_str)
			+ v2vault_separator + xxhr::util::encode64(additional_authenticated_data);

		return encrypted;
	} 

	inline AEAD_decryption_result decrypt(const std::string& password_str, const std::string& input) {
		AEAD_decryption_result result;

		const size_t v2vault_separator_len = v2vault_separator.length();		
		const size_t v2vault_preamble_len = v2vault_preamble.length();

		if(input.rfind(v2vault_preamble, 0) == 0) {
			const uint8_t* password = reinterpret_cast<const uint8_t*>(password_str.c_str());
			
			//
			// v2 vault is formated like:
			// v2:<nonce>:<BASE64 encoded XChaCha20-Poly1305 encrypted message>:<MAC>:<base64 encoded AAD (additional authenticated data)>
			//

			/* Getting the nonce / IV */
			size_t nonce_end   = input.find(v2vault_separator, v2vault_preamble_len);	// find the second separator
			std::string nonce_str = xxhr::util::decode64(input.substr(v2vault_preamble_len, nonce_end  - v2vault_preamble_len));
			const uint8_t* nonce = reinterpret_cast<const uint8_t*>(nonce_str.c_str());

			/* the encrypted part */
			size_t cyphertext_start_offset = nonce_end + v2vault_separator_len;
			size_t cyphertext_end   = input.find(v2vault_separator, cyphertext_start_offset);	// find the 3rd separator
			std::string cyphertext_str = xxhr::util::decode64(input.substr(cyphertext_start_offset, cyphertext_end - cyphertext_start_offset));
			const uint8_t* cyphertext = reinterpret_cast<const uint8_t*>(cyphertext_str.c_str());

			/* the MAC part */
			size_t mac_start_offset = cyphertext_end + v2vault_separator_len;
			size_t mac_end    = input.find(v2vault_separator, mac_start_offset);	// find the 4th separator
			std::string mac_str = xxhr::util::decode64(input.substr(mac_start_offset, mac_end - mac_start_offset));
			const uint8_t*  mac = reinterpret_cast<const uint8_t*>(mac_str.c_str());

			/* the AAD part */
			size_t aad_start_offset = mac_end + v2vault_separator_len;
			std::string aad_str = xxhr::util::decode64(input.substr(aad_start_offset));
			const uint8_t*  aad = reinterpret_cast<const uint8_t*>(aad_str.c_str());

			// decrypt the data using cryptopp's xchachapoly implementation
			XChaCha20Poly1305::Decryption decryption_engine;

			// derive the key using HKDF 
			// using the same nonce a used above
			uint8_t* key{ new uint8_t[decryption_engine.DefaultKeyLength()]{} };
			HKDF<SHA256> hkdf;
			hkdf.DeriveKey(key, decryption_engine.DefaultKeyLength(), 
				password, password_str.length(), 
				nonce, nonce_str.length(),
				NULL, 0
			);

			// initialize & decrypt the actual message
			uint8_t* recovered_text{ new uint8_t[cyphertext_str.length()]{} };

			decryption_engine.SetKeyWithIV(key, decryption_engine.DefaultKeyLength(), nonce, decryption_engine.IVSize());
			bool decryption_succeeeded = decryption_engine.DecryptAndVerify(
				recovered_text, 
				mac, mac_str.length(), 
				nonce, nonce_str.length(), 
				aad, aad_str.length(), 
				cyphertext, cyphertext_str.length()
			);
    		
			if(decryption_succeeeded) {				
				result.plain_text = std::string(reinterpret_cast<char const*>(recovered_text), cyphertext_str.length());
			}
			else {
				throw std::runtime_error("Failed to decrypt vault");
			}

			result.authenticated_data = aad_str;
			result.is_legacy_vault = false;
		}
		else {
			// handle the "legacy" vault
			std::string plain_buffer;
			StringSource ss(input, true,
			new Base64Decoder(
						new Vault_v1_DataDecryptorWithMAC(
							reinterpret_cast<const uint8_t*>(password_str.data()), password_str.size(),
							new StringSink(plain_buffer)
						)
			)
			);

			result.plain_text = plain_buffer;
			result.authenticated_data = "";
			result.is_legacy_vault = true;
		}
		return result;
	}

	//! \brief retrieve tail / AAD part of the encrypted buffer
	inline std::string get_aad_part(const std::string &input) {
		
		// look for the "last" ":" / v2vault_separator 
		int mac_end = input.rfind(v2vault_separator);

		// base64 decode that stuff...
		return xxhr::util::decode64(input.substr(mac_end + v2vault_separator.length()));
	} 

	inline ecies_keypair generate_ecies_keypair() {
		CryptoPP::AutoSeededRandomPool prng;
		ECIES<ECP>::Decryptor decryptor(prng, CryptoPP::ASN1::secp256r1()); // curve25519()
		ECIES<ECP>::Encryptor encryptor(decryptor);
		
		std::string private_key, public_key;
		CryptoPP::HexEncoder hexenc_private(new CryptoPP::StringSink(private_key));
		CryptoPP::HexEncoder hexenc_public(new CryptoPP::StringSink(public_key));

		encryptor.GetPublicKey().Save(hexenc_public);
		decryptor.GetPrivateKey().Save(hexenc_private);

		ecies_keypair result;
		result.private_key = private_key;
		result.public_key = public_key;

		return result;
	}

	inline std::string decrypt_ecies_message(const std::string &cyphertext_hex, const std::string &private_key_hex) {
		CryptoPP::AutoSeededRandomPool prng;

		std::cout << "cyphertext: " << cyphertext_hex << std::endl;

		ECIES<ECP>::Decryptor decryptor(prng, CryptoPP::ASN1::secp256r1());

		CryptoPP::StringSource priv_key_source(private_key_hex, true, new CryptoPP::HexDecoder());		
		decryptor.AccessPrivateKey().Load(priv_key_source);
		decryptor.AccessPrivateKey().ThrowIfInvalid(prng, 3);
		std::cout << "loaded private key" << std::endl;

		std::string cyphertext_plain;		
		CryptoPP::StringSource ss(cyphertext_hex, true,
			new CryptoPP::HexDecoder(
				new CryptoPP::StringSink(cyphertext_plain)
			) // HexDecoder
		); // StringSource

		std::cout << "cyphertext plain: " << cyphertext_plain << std::endl;

		std::string cleartext; // decrypted message
    	CryptoPP::StringSource s (cyphertext_plain, true, new CryptoPP::PK_DecryptorFilter(prng, decryptor, new CryptoPP::StringSink(cleartext) ) );

		std::cout  << "cyphertext plain: " << cleartext << std::endl;
		return cleartext;
	}


	inline std::string encrypt_ecies_message(const std::string &cleartext, const std::string &public_key_hex) {
		CryptoPP::AutoSeededRandomPool prng;		

		// load the key...
		CryptoPP::StringSource pub_key_source(public_key_hex, true, new CryptoPP::HexDecoder());

		// init the encryptor
		ECIES<ECP>::Encryptor encryptor;
		encryptor.AccessPublicKey().Load(pub_key_source);
		encryptor.AccessPublicKey().ThrowIfInvalid(prng, 3);

		std::string encrypted_buffer; // encrypted message
    	CryptoPP::StringSource s (cleartext, true, new CryptoPP::PK_EncryptorFilter(prng, encryptor, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encrypted_buffer) ) ) );
		std::cout << "ency:" << encrypted_buffer << std::endl;

		return encrypted_buffer;
	}
}
#pragma once

#include <string>
#include <cstdint>

#include <cryptopp/default.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>

namespace tipi::detail {

using CryptoPP::DefaultEncryptorWithMAC;
using CryptoPP::DefaultDecryptorWithMAC;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::FileSource;
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

using CryptoPP::AES;
using CryptoPP::SHA256;
using CryptoPP::HMAC;
using CryptoPP::DataParametersInfo;
using CryptoPP::DataEncryptorWithMAC;
using CryptoPP::DataDecryptorWithMAC;
using CryptoPP::SimpleProxyFilter;

const size_t SALT_SIZE = 8;
const size_t ITERATIONS = 2500;
using DataEncryptorTipiVault = DataEncryptorWithMAC <
	AES,SHA256,
	HMAC<SHA256>,
	DataParametersInfo<
		AES::BLOCKSIZE, AES::DEFAULT_KEYLENGTH, HMAC<SHA256>::DIGESTSIZE, SALT_SIZE, ITERATIONS 
	>>;

using DataDecryptorTipiVault = DataDecryptorWithMAC <
	AES,SHA256,
	HMAC<SHA256>,
	DataParametersInfo<
		AES::BLOCKSIZE, AES::DEFAULT_KEYLENGTH, HMAC<SHA256>::DIGESTSIZE, SALT_SIZE, ITERATIONS 
	>>;


	inline std::string encrypt(const std::string& password, const std::string& plain_buffer) {
		std::string encrypted;
	 	StringSource ss(plain_buffer, true,
			new DataEncryptorTipiVault(
					reinterpret_cast<const uint8_t*>(password.data()), password.size(),
          new Base64Encoder(
            new StringSink(encrypted),
            false /* no newline */
          )
				)
		); 

		return encrypted;
	} 

	inline std::string decrypt(const std::string& password, const std::string& encrypted_buffer) {
		std::string plain_buffer;
		StringSource ss(encrypted_buffer, true,
        new Base64Decoder(
					new DataDecryptorTipiVault(
						reinterpret_cast<const uint8_t*>(password.data()), password.size(),
						new StringSink(plain_buffer)
					)
        )
		);		

		return plain_buffer;
	}
}

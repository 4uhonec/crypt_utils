#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <string>
#include <iostream>

#define RSA_KEY_LENGTH_BITS 1024
#define AES_CBC_KEY_SIZE 16

using std::cout;
using std::endl;

class Base64
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};

std::string Base64::encode(const std::string& str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		) // Base64Encoder
	); // StringSource

	return encoded;
}

std::string Base64::decode(const std::string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}

class AES{
	private:
		unsigned char _key[AES_CBC_KEY_SIZE];
	public:
		AES();

		static unsigned char* generate_key(unsigned char* buffer, unsigned int length);
		const unsigned char* get_key() const;

		std::string encrypt(const char* plain, unsigned int length);
		std::string decrypt(const char* cipher, unsigned int length);

};

AES::AES()
{
	generate_key(_key, AES_CBC_KEY_SIZE);
}

unsigned char* AES::generate_key(unsigned char* buffer, unsigned int length){
	CryptoPP::AutoSeededRandomPool rng;
	rng.GenerateBlock(buffer, length);
	return buffer;
}

const unsigned char* AES::get_key() const{
	return _key;
}

std::string AES::encrypt(const char* plain, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(_key, AES_CBC_KEY_SIZE);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}


std::string AES::decrypt(const char* cipher, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(_key, AES_CBC_KEY_SIZE);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}

class RSA{
    private:
        CryptoPP::AutoSeededRandomPool _rng;
        CryptoPP::RSA::PrivateKey _privateKey;
        CryptoPP::RSA::PublicKey _publicKey;
    public:
        RSA();
        void generate_keys();
        std::string decrypt(std::string cipher);
        std::string encrypt(std::string str);
        std::string get_public_key();
        std::string get_private_key();
};

RSA::RSA(){}

void RSA::generate_keys(){
	_privateKey.Initialize(_rng, RSA_KEY_LENGTH_BITS);
    _publicKey.AssignFrom(_privateKey);
}
std::string RSA::decrypt(std::string cipher){
	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(cipher, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}
std::string RSA::encrypt(std::string str){
	std::string cipher;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
	CryptoPP::StringSource ss(str, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}
std::string RSA::get_public_key(){
	CryptoPP::RSAFunction publicKey(_privateKey);
	std::string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	return key;
}
std::string RSA::get_private_key(){
	std::string key;
	CryptoPP::StringSink ss(key);
	_privateKey.Save(ss);
	return key;
}

int main(){
    RSA rsa;
    rsa.generate_keys();
	std::string pub = rsa.get_public_key();
	std::string priv = rsa.get_private_key();
	std::string pub_enc = Base64::encode(rsa.get_public_key());
	std::string priv_enc = Base64::encode(rsa.get_private_key());
	cout << pub.size() << endl;
	cout << priv.size() << endl;
	/*for(int i = 0; i<5; i++){
		rsa.generate_keys();
		Base64::decode
	}*/
    return 0;
}
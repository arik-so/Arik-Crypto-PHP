<?php
/**
 * Created by IntelliJ IDEA.
 * User: arik
 * Date: 12/25/15
 * Time: 2:53 PM
 */

namespace ArikCrypto;


class RSA {

	const KEY_MODE_PRIVATE = 'private';
	const KEY_MODE_PUBLIC = 'public';
	
	public static function generateKeyPair($bitSize = 2048) {

		$strangeKeyPair = openssl_pkey_new(array('private_key_bits' => $bitSize));

		openssl_pkey_export($strangeKeyPair, $privateKey);

		$publicKeyDetails = openssl_pkey_get_details($strangeKeyPair);
		$publicKey = $publicKeyDetails['key'];

		$keyPair = new RSAKeyPair($publicKey, $privateKey);

		return $keyPair;

	}

	public static function encryptAndBase64WithPublic($data, $publicKey) {

		return base64_encode(self::encryptWithPublic($data, $publicKey));
	}

	private static function encryptWithPublic($data, $publicKey) {

		$normalizedKey = self::normalizeKey($publicKey, self::KEY_MODE_PUBLIC);
		openssl_public_encrypt($data, $encryptedString, $normalizedKey);

		return $encryptedString;

	}

	public static function encryptAndBase64WithPrivate($data, $privateKey) {

		return base64_encode(self::encryptWithPrivate($data, $privateKey));
	}

	private static function encryptWithPrivate($data, $privateKey) {

		$normalizedKey = self::normalizeKey($privateKey, self::KEY_MODE_PRIVATE);
		openssl_private_encrypt($data, $decryptedString, $normalizedKey);

		return $decryptedString;

	}

	public static function decryptBase64WithPublic($data, $publicKey) {

		return self::decryptWithPublic(base64_decode($data), $publicKey);
	}

	private static function decryptWithPublic($data, $publicKey) {

		$normalizedKey = self::normalizeKey($publicKey, self::KEY_MODE_PUBLIC);
		openssl_public_decrypt($data, $encryptedString, $normalizedKey);

		return $encryptedString;

	}

	public static function decryptBase64WithPrivate($data, $privateKey) {

		return self::decryptWithPrivate(base64_decode($data), $privateKey);
	}

	private static function decryptWithPrivate($data, $privateKey) {

		$normalizedKey = self::normalizeKey($privateKey, self::KEY_MODE_PRIVATE);
		openssl_private_decrypt($data, $decryptedString, $normalizedKey);

		return $decryptedString;

	}

	private static function normalizeKey($unfilteredKey, $mode = null) {
		// remove decorators
		$undecoratedKey = preg_replace('/-----[A-Za-z ]*-----/', null, $unfilteredKey);
		// remove new lines
		$nonWrappedKey = str_replace("\n", null, $undecoratedKey);
		$rewrappedKey = implode("\n", str_split($nonWrappedKey, 64));

		if ($mode === self::KEY_MODE_PRIVATE) {
			return "-----BEGIN PRIVATE KEY-----\n" . $rewrappedKey . "\n-----END PRIVATE KEY-----\n";
		} else if ($mode === self::KEY_MODE_PUBLIC) {
			return "-----BEGIN PUBLIC KEY-----\n" . $rewrappedKey . "\n-----END PUBLIC KEY-----\n";
		}

		return $rewrappedKey;
	}

}

class RSAKeyPair {

	private $_publicKey;
	private $_privateKey;

	const SIGNATURE_HASH_ALGORITHM = 'sha256';

	public function __construct($publicKey, $privateKey) {

		$this->_publicKey = $publicKey;
		$this->_privateKey = $privateKey;

	}

	public function getPublicKey() { return $this->_publicKey; }

	public function getPrivateKey() { return $this->_privateKey; }

	public function encrypt($data) {
		return RSA::encryptAndBase64WithPublic($data, $this->getPublicKey());
	}

	public function decrypt($data) {
		return RSA::decryptBase64WithPrivate($data, $this->getPrivateKey());
	}

	public function sign($data, $hash = false){
		if ($hash) {
			$data = hash(self::SIGNATURE_HASH_ALGORITHM, $data);
		}
		return RSA::encryptAndBase64WithPrivate($data, $this->getPrivateKey());
	}

	public function verify($signature, $original, $hash = false){
		if ($hash){
			$original = hash(self::SIGNATURE_HASH_ALGORITHM, $original);
		}
		$reconstructed = RSA::decryptBase64WithPublic($signature, $this->getPublicKey());
		return $reconstructed === $original;
	}

}

<?php
/**
 * Created by IntelliJ IDEA.
 * User: arik
 * Date: 12/28/15
 * Time: 11:09 AM
 */

namespace ArikCrypto;


use BitcoinPHP\BitcoinECDSA\BitcoinECDSA;

class ECC {

	private static $ecdsaInstance = null;

	public static function generateKeyPair() {
		$ecdsa = self::getECDSAInstance();
		$ecdsa->generateRandomPrivateKey(mcrypt_create_iv(32));

		$keyPair = new ECCKeyPair($ecdsa->getPubKey(), $ecdsa->getPrivateKey());
		return $keyPair;
	}

	private static function getECDSAInstance() {
		if (!(self::$ecdsaInstance instanceof BitcoinECDSA)) {
			self::$ecdsaInstance = new BitcoinECDSA();
		}
		return self::$ecdsaInstance;
	}

	public static function sign($data, $privateKey) {
		$ecdsa = self::getECDSAInstance();
		$ecdsa->setPrivateKey($privateKey);
		return $ecdsa->signMessage($data);
	}

	public static function verify($signature, $original, $publicKey) {
		$ecdsa = self::getECDSAInstance();
		$address = $ecdsa->getUncompressedAddress(false, $publicKey);
		return $ecdsa->checkSignatureForMessage($address, $signature, $original);
	}

	public static function diffieHellman($publicKey, $privateKey) {
		$ecdsa = self::getECDSAInstance();
		$publicKeyPoints = $ecdsa->getPubKeyPointsWithDerPubKey($publicKey);
		$normalizedPublicKey = [
			'x' => '0x' . $publicKeyPoints['x'],
			'y' => '0x' . $publicKeyPoints['y']
		];
		$product = $ecdsa->mulPoint($privateKey, $normalizedPublicKey);
		$secretPoints = [
			'x' => gmp_strval($product['x'], 16),
			'y' => gmp_strval($product['y'], 16)
		];
		$symmetricKey = $ecdsa->getDerPubKeyWithPubKeyPoints($secretPoints);
		$aesCompatibleKey = self::exportKeyForAES($symmetricKey);
		return $aesCompatibleKey;
	}

	public static function exportKeyForAES($symmetricKey) {
		// the key is hexadecimal
		// the data must be 32 characters long
		// $trimmedData = substr($symmetricKey, 0, 64);
		// $rawData = hex2bin($trimmedData);

		$rawData = hash('sha256', $symmetricKey, true);
		$aesKey = base64_encode($rawData);
		return $aesKey;
	}

}

class ECCKeyPair {

	private $_publicKey;
	private $_privateKey;

	public function __construct($publicKey, $privateKey) {
		$this->_publicKey = $publicKey;
		$this->_privateKey = $privateKey;
	}

	public function sign($data) {
		return ECC::sign($data, $this->getPrivateKey());
	}

	public function getPrivateKey() { return $this->_privateKey; }

	public function verify($signature, $original) {
		return ECC::verify($signature, $original, $this->getPublicKey());
	}

	public function getPublicKey() { return $this->_publicKey; }

	public function calculateSymmetricKey($publicKey = null) {
		if ($publicKey == null) {
			$publicKey = $this->getPublicKey();
		}
		return ECC::diffieHellman($publicKey, $this->getPrivateKey());
	}

}

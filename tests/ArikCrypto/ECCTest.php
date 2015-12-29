<?php
/**
 * Created by IntelliJ IDEA.
 * User: arik
 * Date: 12/28/15
 * Time: 11:09 AM
 */

namespace Tests\ArikCrypto;

use ArikCrypto\AES;
use ArikCrypto\ECC;
use BitcoinPHP\BitcoinECDSA\BitcoinECDSA;

class ECCTest extends \PHPUnit_Framework_TestCase {

	public function testDiffieHellman() {

		$ecdsa1 = new BitcoinECDSA();
		$ecdsa1->generateRandomPrivateKey(mcrypt_create_iv(32));

		$ecdsa2 = new BitcoinECDSA();
		$ecdsa2->generateRandomPrivateKey(mcrypt_create_iv(32));

		$pub1 = $ecdsa1->getPubKeyPoints();
		$priv1 = $ecdsa1->getPrivateKey();
		$priv1B = $ecdsa1->getWif();

		var_dump($priv1);
		var_dump($priv1B);

		$pub2 = $ecdsa2->getPubKeyPoints();
		$priv2 = $ecdsa2->getPrivateKey();

		$der1A = $ecdsa2->getDerPubKeyWithPubKeyPoints($pub1);
		$der1B = $ecdsa1->getDerPubKeyWithPubKeyPoints($pub1);

		$this->assertEquals($der1A, $der1B);

		$productA = $this->diffieHellman($pub1, $priv2);
		$productB = $this->diffieHellman($pub2, $priv1);

		$this->assertEquals($productA, $productB);

	}

	public function testRawSigning() {

		$ecdsa = new BitcoinECDSA();
		$ecdsa->generateRandomPrivateKey(mcrypt_create_iv(32));

		$original = 'Hello World';
		$messageSignature = $ecdsa->signMessage($original);

		// change the private key
		$ecdsa->generateRandomPrivateKey(mcrypt_create_iv(32));

		$check1 = $ecdsa->checkSignatureForMessage($ecdsa->getUncompressedAddress(), $messageSignature, $original);
		$this->assertTrue($check1, 'signature correct');
	}

	public function testSigning() {

		$keyPair = ECC::generateKeyPair();
		$original = 'Hello World!';

		$signature = $keyPair->sign($original);
		$this->assertTrue($keyPair->verify($signature, $original), 'signature correct');

	}

	public function testSymmetricEncryption() {

		$keyPair1 = ECC::generateKeyPair();
		$keyPair2 = ECC::generateKeyPair();

		$symmetricKeyA = $keyPair1->calculateSymmetricKey($keyPair2->getPublicKey());
		$symmetricKeyB = $keyPair2->calculateSymmetricKey($keyPair1->getPublicKey());
		$this->assertEquals($symmetricKeyA, $symmetricKeyB);

		// if I wanna encrypt data only for myself to see
		$myKey = $keyPair1->calculateSymmetricKey();
		$iv = AES::generateInitializationVector();
		$original = 'Hello World!';

		$encrypted = AES::encryptAndBase64($original, $myKey, $iv);
		$decrypted = AES::decryptBase64($encrypted, $myKey, $iv);
		$this->assertEquals($original, $decrypted, 'encryption works');

	}

	private function diffieHellman($publicKeyPoints, $privateKey) {
		$ecdsa = new BitcoinECDSA();
		$normalizedPublicKey = [
			'x' => '0x' . $publicKeyPoints['x'],
			'y' => '0x' . $publicKeyPoints['y']
		];
		$product = $ecdsa->mulPoint($privateKey, $normalizedPublicKey);
		$secretPoints = [
			'x' => gmp_strval($product['x'], 16),
			'y' => gmp_strval($product['y'], 16)
		];
		return $secretPoints;
	}

}

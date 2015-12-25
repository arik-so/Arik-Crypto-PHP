<?php

/**
 * Created by IntelliJ IDEA.
 * User: arik
 * Date: 12/25/15
 * Time: 3:30 PM
 */
class AESTest extends PHPUnit_Framework_TestCase {

	public function testKeyGeneration() {
		$key = \ArikCrypto\AES::generateKey();
		$rawKey = base64_decode($key);
		$this->assertEquals(32, strlen($rawKey));
		echo $key;
	}

	public function testInitializationVectorGeneration() {
		$key = \ArikCrypto\AES::generateInitializationVector();
		$rawKey = base64_decode($key);
		$this->assertEquals(16, strlen($rawKey));
		echo $key;
	}

	public function testEncryption(){
		$key = \ArikCrypto\AES::generateKey();
		$iv = \ArikCrypto\AES::generateInitializationVector();
		$original = 'Hello World!';
		$encrypted = \ArikCrypto\AES::encryptAndBase64($original, $key, $iv);
		$decrypted = ArikCrypto\AES::decryptBase64($encrypted, $key, $iv);
		$this->assertEquals($original, $decrypted);
	}
}

<?php
/**
 * Created by IntelliJ IDEA.
 * User: arik
 * Date: 12/25/15
 * Time: 4:33 PM
 */

namespace Tests\ArikCrypto;


use ArikCrypto\AES;

class AESTest extends \PHPUnit_Framework_TestCase {

	public function testKeyGeneration() {
		$key = AES::generateKey();
		$rawKey = base64_decode($key);
		$this->assertEquals(32, strlen($rawKey));
		echo $key;
	}

	public function testInitializationVectorGeneration() {
		$key = AES::generateInitializationVector();
		$rawKey = base64_decode($key);
		$this->assertEquals(16, strlen($rawKey));
		echo $key;
	}

	public function testEncryption(){
		$key = \ArikCrypto\AES::generateKey();
		$iv = \ArikCrypto\AES::generateInitializationVector();
		$original = 'Hello World!';
		$encrypted = AES::encryptAndBase64($original, $key, $iv);
		$decrypted = AES::decryptBase64($encrypted, $key, $iv);
		$this->assertEquals($original, $decrypted);
	}

}

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
	}

	public function testInitializationVectorGeneration() {
		$key = AES::generateInitializationVector();
		$rawKey = base64_decode($key);
		$this->assertEquals(16, strlen($rawKey));
	}

	public function testEncryption() {
		$key = AES::generateKey();
		$iv = AES::generateInitializationVector();
		$original = 'Hello World!';
		$encrypted = AES::encrypt($original, $key, $iv);

		/*var_dump($key);
		var_dump($iv);
		var_dump($encrypted);*/

		$decrypted = AES::decrypt($encrypted, $key, $iv);
		$this->assertEquals($original, $decrypted);
	}

	public function testCrossPlatformDecryption() {
		$key = '9u4O/OOB7wuX7CYriDmlABT6NJQVQGHuC5qPQ5EmWsU=';
		$iv = 'YB6jf1MP+n3OpOr+hiEsmQ==';
		$encrypted = 'IbU6hBo8JV+cEfzzHLZnnQ==';
		$decrypted = AES::decrypt($encrypted, $key, $iv);
		$expected = 'Hello World!';
		$this->assertEquals($expected, $decrypted, 'decryption works');
	}

	public function testDerivation(){
		$input = 'presumablyADiffieHellmanResult';
		$derivation = AES::deriveKey($input);
		$arbitraryText = 'correcthorsebatterystaple';
		$derivedKey = AES::deriveKey($arbitraryText);
		// var_dump($derivedKey);
		$this->assertEquals('CfSmnHxb6DEdPg7+/+LmPrbHIjFb6e0Z5fzv+psTKSM=', $derivation, 'derivation works');
	}

}

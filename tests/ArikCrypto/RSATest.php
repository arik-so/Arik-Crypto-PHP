<?php

/**
 * Created by IntelliJ IDEA.
 * User: arik
 * Date: 12/25/15
 * Time: 2:59 PM
 */

namespace Tests\ArikCrypto;

use ArikCrypto\RSA;

class RSATest extends \PHPUnit_Framework_TestCase {

	public function testKeyPairGeneration() {
		$keyPair = RSA::generateKeyPair();
		$this->assertNotEmpty($keyPair->getPrivateKey());
		$this->assertNotEmpty($keyPair->getPublicKey());
	}

	public function testEncryption() {
		$keyPair = RSA::generateKeyPair();
		$original = 'Hello World';
		$encrypted = $keyPair->encrypt($original);
		$decrypted = $keyPair->decrypt($encrypted);
		$this->assertEquals($original, $decrypted);
	}

	public function testSigning() {
		$keyPair = RSA::generateKeyPair();
		$original = 'Hello World';
		$hashedSignature = $keyPair->sign($original, true);
		$unhashedSignature = $keyPair->sign($original, false);
		$this->assertTrue($keyPair->verify($hashedSignature, $original, true));
		$this->assertTrue($keyPair->verify($unhashedSignature, $original, false));
	}

}

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

	public function testImporting() {

		$keyPair = RSA::generateKeyPair();

		$publicKeyData = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3U+m8lm24bPm6G7fN4o9cBdQZrSz65cy/XliPRxPWdGMWw06R02UGaXRFV97cqGCLuj1lg3JRkK5WiVKK8nnusOnMBUvhdFLWOk3zOia5Fx+6IK3m9LjLgwDYJ473rJgNFG6W3zeBZdgvTMpCrOmT7EN1RS5WgVTXBfQ2dvxksqJqgwqwr50zXqp5K2twXp89Gy+l4M46WCcT0e8DtZ3Rmmwz2aMZzGiT/jqeqLBHLxvWM9WQkgT91zTXmI2et1Gogpc0UnVR/pQ0EBozA1WjhHdmSPUIIGVsvZFO1I+0d9OKqYGN0e2rL8YH58qXtWQ3Q+275VUuiwTc8ZPlHCu9QIDAQAB';
		// $publicKeyData = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3U+m8lm24bPm6G7fN4o9cBdQZrSz65cy/XliPRxPWdGMWw06R02UGaXRFV97cqGCLuj1lg3JRkK5WiVKK8nnusOnMBUvhdFLWOk3zOia5Fx+6IK3m9LjLgwDYJ473rJgNFG6W3zeBZdgvTMpCrOmT7EN1RS5WgVTXBfQ2dvxksqJqgwqwr50zXqp5K2twXp89Gy+l4M46WCcT0e8DtZ3Rmmwz2aMZzGiT/jqeqLBHLxvWM9WQkgT91zTXmI2et1Gogpc0UnVR/pQ0EBozA1WjhHdmSPUIIGVsvZFO1I+0d9OKqYGN0e2rL8YH58qXtWQ3Q+275VUuiwTc8ZPlHCu9QIDAQAB';
		$privateKeyData = 'MIIEogIBAAKCAQEA3U+m8lm24bPm6G7fN4o9cBdQZrSz65cy/XliPRxPWdGMWw06R02UGaXRFV97cqGCLuj1lg3JRkK5WiVKK8nnusOnMBUvhdFLWOk3zOia5Fx+6IK3m9LjLgwDYJ473rJgNFG6W3zeBZdgvTMpCrOmT7EN1RS5WgVTXBfQ2dvxksqJqgwqwr50zXqp5K2twXp89Gy+l4M46WCcT0e8DtZ3Rmmwz2aMZzGiT/jqeqLBHLxvWM9WQkgT91zTXmI2et1Gogpc0UnVR/pQ0EBozA1WjhHdmSPUIIGVsvZFO1I+0d9OKqYGN0e2rL8YH58qXtWQ3Q+275VUuiwTc8ZPlHCu9QIDAQABAoIBAAh2ZUHbIF0dDfVRWAO9q3+/xHlI66BUlcSPgawoivg6RQ2uQc48Ly+T4ZzZm9TUTDATBGEKgenH32KNDnsCK3Q+ywPRq5GIYUMzF8kkE9grmUa2yOKSe9Fk8DQfmNZ5J6iYf3HEIpFAKpjRff5ExFVDxe2h7zx7+6YH2xqZiHE+auHG88PaiKRAdjTRIxA5A/SyNHzQ9q/qenyTBUVfmuXvH78rcHjWF3p5xZclDFi0Al6snaGxMxjuk2yph3W6nKRizfJj0u984gjeJueJCOiu3JaXWHQtF3fgQ1EP9dXCKeBeWT9tCTuYvN/mSHplbQlqI6I012Y5wwunDax3Y0ECgYEB1CXZkZZoWC6WZAVAhq67jo2PMOpkIYPYxq5ODrHMEIUCzVVe1UURpFD3CjYMywwlZgru4yMSEUGgbu3lgFQv6DEzeQxHwR9yDd6quahL4YNcieFv9+swXD1s7dAVJ4Jmly3QYJTEYhcxzZuDDYUu7Jxxfkhek9AAwZaBGFn3d/kCgYB5BVaahWKGKyPENbZOxlNyNgTdQLBoAlJDpOhToZlj8TVGINR4Yc/e4hJrGtdkatvHclj2DY4xEyOIRXwWDFBev1nRdsfrXeAp1s0TSImiobdxzpePBzCSPCcmqGattgj+pV3';
		// $privateKeyData = 'MIIBCgKCAQEA3U+m8lm24bPm6G7fN4o9cBdQZrSz65cy/XliPRxPWdGMWw06R02UGaXRFV97cqGCLuj1lg3JRkK5WiVKK8nnusOnMBUvhdFLWOk3zOia5Fx+6IK3m9LjLgwDYJ473rJgNFG6W3zeBZdgvTMpCrOmT7EN1RS5WgVTXBfQ2dvxksqJqgwqwr50zXqp5K2twXp89Gy+l4M46WCcT0e8DtZ3Rmmwz2aMZzGiT/jqeqLBHLxvWM9WQkgT91zTXmI2et1Gogpc0UnVR/pQ0EBozA1WjhHdmSPUIIGVsvZFO1I+0d9OKqYGN0e2rL8YH58qXtWQ3Q+275VUuiwTc8ZPlHCu9QIDAQABMIIEogIBAAKCAQEA3U+m8lm24bPm6G7fN4o9cBdQZrSz65cy/XliPRxPWdGMWw06R02UGaXRFV97cqGCLuj1lg3JRkK5WiVKK8nnusOnMBUvhdFLWOk3zOia5Fx+6IK3m9LjLgwDYJ473rJgNFG6W3zeBZdgvTMpCrOmT7EN1RS5WgVTXBfQ2dvxksqJqgwqwr50zXqp5K2twXp89Gy+l4M46WCcT0e8DtZ3Rmmwz2aMZzGiT/jqeqLBHLxvWM9WQkgT91zTXmI2et1Gogpc0UnVR/pQ0EBozA1WjhHdmSPUIIGVsvZFO1I+0d9OKqYGN0e2rL8YH58qXtWQ3Q+275VUuiwTc8ZPlHCu9QIDAQABAoIBAAh2ZUHbIF0dDfVRWAO9q3+/xHlI66BUlcSPgawoivg6RQ2uQc48Ly+T4ZzZm9TUTDATBGEKgenH32KNDnsCK3Q+ywPRq5GIYUMzF8kkE9grmUa2yOKSe9Fk8DQfmNZ5J6iYf3HEIpFAKpjRff5ExFVDxe2h7zx7+6YH2xqZiHE+auHG88PaiKRAdjTRIxA5A/SyNHzQ9q/qenyTBUVfmuXvH78rcHjWF3p5xZclDFi0Al6snaGxMxjuk2yph3W6nKRizfJj0u984gjeJueJCOiu3JaXWHQtF3fgQ1EP9dXCKeBeWT9tCTuYvN/mSHplbQlqI6I012Y5wwunDax3Y0ECgYEB1CXZkZZoWC6WZAVAhq67jo2PMOpkIYPYxq5ODrHMEIUCzVVe1UURpFD3CjYMywwlZgru4yMSEUGgbu3lgFQv6DEzeQxHwR9yDd6quahL4YNcieFv9+swXD1s7dAVJ4Jmly3QYJTEYhcxzZuDDYUu7Jxxfkhek9AAwZaBGFn3d/kCgYB5BVaahWKGKyPENbZOxlNyNgTdQLBoAlJDpOhToZlj8TVGINR4Yc/e4hJrGtdkatvHclj2DY4xEyOIRXwWDFBev1nRdsfrXeAp1s0TSImiobdxzpePBzCSPCcmqGattgj+pV3185hOmDYAsfYSkLjiEoc7Rh5G1TYEsfJVuDhF3QKBgQEWxAcfc3Hk+LDjFGGNEaVryI24sgo4DtvZy1d91o/OUnYNsUVMN9m+f9vrP640hqIKdn4z0OFkVzDifVTJKthwKkQdU5uyuzfeXHZLIZU1z1QeYpibB3h/pLAlmF/QbA0M/uHzcQLT6j3k0jKirWj4ylumuA9hc13P6QAscP40eQKBgCWkI2usURiqElXU3v9hcFL1uk2W8UdocW3YvOpGOQ981rUZQPywb5dDebcWgigZlIJUbpcZYECjU0nvUskIy3aszaL47vWmHTLmPKLizOxooEYlm75A3jqduw+rEUS2edW6WZ9GRPktHp7Yu1DK8rZeTPGCvagKaOLM9jLzOY2BAoGALYPm/3R9fm1Or6r/DWcWtXIIwRG6tBF+1n5Pjqp9N1ZxoOGmnLWXE5mgLRTU1fpyQ+c4C/J8X3ujauaR12oqfUvmWAfMSCgsA6dWKbouOlZe2fBXwEkeAYgHpHnEEhy+2kzVWeV2tTWDhJPuoc1FhYe6RgONKVxYYqn6/fbAnQg=';
		$original = 'Hello World!';

		$publicExperiment2 = '-----BEGIN PUBLIC KEY-----'.PHP_EOL.wordwrap($publicKeyData, 64, PHP_EOL, true).PHP_EOL.'-----END PUBLIC KEY-----';
		$privateExperiment2 = '-----BEGIN RSA PRIVATE KEY-----'.PHP_EOL.wordwrap($privateKeyData, 64, PHP_EOL, true).PHP_EOL.'-----END RSA PRIVATE KEY-----';


//		echo PHP_EOL.PHP_EOL.'TESTING PUBLIC KEYS';
//		echo PHP_EOL.$keyPair->getPublicKey().PHP_EOL;
//		echo PHP_EOL.$publicExperiment2.PHP_EOL;

		echo PHP_EOL.PHP_EOL.'TESTING PRIVATE KEYS: '.strlen($keyPair->getPrivateKey()) .' vs '.strlen($privateExperiment2);
		echo PHP_EOL.$keyPair->getPrivateKey().PHP_EOL;
		echo PHP_EOL.$privateExperiment2.PHP_EOL;


		$extraction = openssl_get_privatekey($privateExperiment2);
		var_dump($extraction);

		$keyDetails = openssl_pkey_get_details($extraction);
		var_dump($keyDetails);
		die();




		$encrypted = RSA::encryptAndBase64WithPublic($original, $publicExperiment2);
		$decrypted = RSA::decryptBase64WithPrivate($encrypted, $privateExperiment2);
	}

}

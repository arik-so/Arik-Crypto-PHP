<?php

/**
 * Created by IntelliJ IDEA.
 * User: arik
 * Date: 12/25/15
 * Time: 2:59 PM
 */

namespace Tests\ArikCrypto;

use ArikCrypto\RSA;
use ArikCrypto\RSAKeyPair;

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

	public function testAndroidImportedSigning() {

		$referenceKeyPair = RSA::generateKeyPair(4096);

		$publicKeyKernel = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2wM7KOTr3SvOpBPnX/6w
3bXAe7MCgR97QXNDwUPYdplPQXowmRHx6SjUiSPQGQg79evW32+fuYlpxVTX8VdH
Irx5pOCeohoxh9lokCUKLHhqMB5l8pDmt4r8GEu1UHPQFMtAkp8QJ1UsEbxOXHfr
W0MBFNQ644iQh8LXu+NH4zee1yMIgjew7Gff+UA2KOdt0nKG32WoY0b5SGcr9rPb
ciYNb8hHo06A3af2/hpxE1Mv/2XKkzkN6V+UzNxoMlhssnlfe8a8WeBYTdgh87pD
LzUWeFoaxkkZQK5dPjZxKcXtR2Rjo4sZj9wSt/ACgCBp7yrt1aB5osv7/JPbnPQv
uXK/9MWUsxikesFwHgJkJxR/MK90nuvZzAkXwihGu0PTSt5y2Ey5nVqIeVBcgBSV
sB4HW4XeMFkt3tJdMty14PXHny/951TcBGTkd1Gj6WeUs1g1at+FiU/GdU2uXbiE
XDr+TRByEVg74TGIalHcDlMEzJ8Dpjx+PC3OE4YDl3gFlKTe+soP9fFxv8K1Fcf6
/vNvIhaJmjtfAwxbLafk4N5WEnfzI2IR+9DyBo7BnlHsTa39SaMdvMB8imyOBFTy
kt656lpGDZxeTSQ1USMLc+AJQg3vSBthzazr4XqHrye9R39E4/VwN+Luf/uXBr0b
QPjtWPCheta1ZgVX1rIfucsCAwEAAQ==';

		$privateKeyKernel = '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
LJu3/c2LXMYRFQ+c1Zv0TtyjEGxXtBpC';

		$javaKeyPair = new RSAKeyPair($publicKeyKernel, $privateKeyKernel);

		$original = 'Hello World';
		$hashedSignature = $javaKeyPair->sign($original, true);
		$unhashedSignature = $javaKeyPair->sign($original, false);
		$this->assertTrue($javaKeyPair->verify($hashedSignature, $original, true));
		$this->assertTrue($javaKeyPair->verify($unhashedSignature, $original, false));

	}

}

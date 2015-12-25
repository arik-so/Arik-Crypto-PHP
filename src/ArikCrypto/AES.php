<?php
/**
 * Created by IntelliJ IDEA.
 * User: arik
 * Date: 12/25/15
 * Time: 3:25 PM
 */

namespace ArikCrypto;


class AES {

	public static function generateKey(){

		return base64_encode(mcrypt_create_iv(32));

	}

	public static function generateInitializationVector(){

		return base64_encode(mcrypt_create_iv(16));

	}

	public static function encrypt($input, $key, $iv) {

		$size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
		$input = AES::pkcs5_pad($input, $size);
		$td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
		mcrypt_generic_init($td, $key, $iv);
		$data = mcrypt_generic($td, $input);
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
		// $data = base64_encode($data);

		return $data;

	}

	private static function pkcs5_pad ($text, $blocksize) {
		$pad = $blocksize - (strlen($text) % $blocksize);
		return $text . str_repeat(chr($pad), $pad);
	}

	public static function decrypt($input, $key, $iv) {
		$decrypted= mcrypt_decrypt(
			MCRYPT_RIJNDAEL_128,
			$key,
			$input,
			MCRYPT_MODE_CBC,
			$iv
		);
		$dec_s = strlen($decrypted);
		$padding = ord($decrypted[$dec_s-1]);
		$decrypted = substr($decrypted, 0, -$padding);
		return $decrypted;
	}

	public static function decryptBase64($input, $key, $iv){
		return self::decrypt(base64_decode($input), base64_decode($key), base64_decode($iv));
	}

	public static function encryptAndBase64($input, $key, $iv){
		return base64_encode(self::encrypt($input, base64_decode($key), base64_decode($iv)));
	}

}

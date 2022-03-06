<?php
/**
 * Copyright (C)  2018 youri.
 * Permission is granted to copy, distribute and/or modify this document
 * under the terms of the GNU Free Documentation License, Version 1.3
 * or any later version published by the Free Software Foundation;
 * with no Invariant Sections, no Front-Cover Texts, and no Back-Cover Texts.
 * A copy of the license is included in the section entitled "GNU
 * Free Documentation License".
 *
 * @date: 9/13/18 / 9:44 AM
 * @author: Youri van den Bogert
 * @url: http://www.xl-knowledge.nl/
 */

namespace MediaWiki\Extension\GoogleAuthenticator;

class GoogleAuthenticator {

	/**
	 * Default secret length
	 * @var int
	 */
	const SECRET_LENGTH = 24;

	/**
	 * Code length (6 in Google's Authenticator App
	 * @var int
	 */
	const CODE_LENGTH = 6;

	/**
	 * Verifies the given code
	 *
	 * @param string|null $secret
	 * @param string $code
	 * @param int $discrepancy
	 * @param null $currentTimeSlice
	 * @return bool
	 */
	public static function verifyCode( $secret, $code, $discrepancy = 1, $currentTimeSlice = null ) {
		if ( $currentTimeSlice === null ) {
			$currentTimeSlice = floor( time() / 30 );
		}

		if ( strlen( $code ) != 6 ) {
			return false;
		}

		for ( $i = -$discrepancy; $i <= $discrepancy; ++$i ) {
			$calculatedCode = self::getCode( $secret, $currentTimeSlice + $i );
			if ( self::timingSafeEquals( $calculatedCode, $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Generates a secret code
	 *
	 * @throws \Exception
	 * @return string
	 */
	public static function generateSecret() {
		$secretLength = self::SECRET_LENGTH;

		// Valid secret lengths are 80 to 640 bits
		if ( $secretLength < 16 || $secretLength > 128 ) {
			throw new \Exception( 'Bad secret length' );
		}

		// Set accepted characters
		$validChars = self::getBase32LookupTable();

		// Generates a strong secret
		$secret = random_bytes( $secretLength );
		$secretEnc = '';
		for ( $i = 0; $i < strlen( $secret ); $i++ ) {
			$secretEnc .= $validChars[ord( $secret[$i] ) & 31];
		}

		return $secretEnc;
	}

	/**
	 * Returns the QR code as image or url
	 *
	 * @param string $secret
	 * @param string $username
	 * @param int $width
	 * @param int $height
	 * @param bool $returnAsImage
	 * @throws \Exception
	 * @return mixed
	 */
	public static function getQRCode( $secret, $username, $width = 200, $height = 200, $returnAsImage = true ) {
		global $wgGAIssuer, $wgSitename;

		// Replace sitename to $wgSitename
		$issuer = str_replace( '__SITENAME__', $wgSitename, $wgGAIssuer );

		// Set CHL
		$chl = urlencode( "otpauth://totp/{$username}?secret={$secret}" );
		$chl .= urlencode( "&issuer=" . urlencode( "{$issuer}" ) );

		// Set the sourceUrl
		$sourceUrl = "https://chart.googleapis.com/chart?chs={$width}x{$height}&chld=H|0&cht=qr&chl={$chl}";

		return ( $returnAsImage )
			? file_get_contents( $sourceUrl )
			: $sourceUrl;
	}

	/**
	 * Get array with all 32 characters for decoding from/encoding to base32.
	 *
	 * @return array
	 */
	private static function getBase32LookupTable() {
		return [
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', // 7
			'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
			'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
			'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31,
			'='
		];
	}

	/**
	 * @param string|null $secret
	 * @param null $timeSlice
	 * @return string
	 */
	private static function getCode( $secret, $timeSlice = null ) {
		if ( $timeSlice === null ) {
			$timeSlice = floor( time() / 30 );
		}

		$secretkey = self::base32Decode( $secret );

		// Pack time into binary string
		$time = chr( 0 ) . chr( 0 ) . chr( 0 ) . chr( 0 ) . pack( 'N*', $timeSlice );
		// Hash it with users secret key
		$hm = hash_hmac( 'SHA1', $time, $secretkey, true );
		// Use last nipple of result as index/offset
		$offset = ord( substr( $hm, -1 ) ) & 0x0F;
		// grab 4 bytes of the result
		$hashpart = substr( $hm, $offset, 4 );

		// Unpak binary value
		$value = unpack( 'N', $hashpart );
		$value = $value[1];
		// Only 32 bits
		$value = $value & 0x7FFFFFFF;

		$modulo = pow( 10, self::CODE_LENGTH );

		return str_pad( $value % $modulo, self::CODE_LENGTH, '0', STR_PAD_LEFT );
	}

	/**
	 * Helper class to decode base32.
	 *
	 * @param string|null $secret
	 *
	 * @return bool|string
	 */
	private static function base32Decode( $secret ) {
		if ( empty( $secret ) ) {
			return '';
		}

		$base32chars = self::getBase32LookupTable();
		$base32charsFlipped = array_flip( $base32chars );

		$paddingCharCount = substr_count( $secret, $base32chars[32] );
		$allowedValues = [ 6, 4, 3, 1, 0 ];
		if ( !in_array( $paddingCharCount, $allowedValues ) ) {
			return false;
		}
		for ( $i = 0; $i < 4; ++$i ) {
			if ( $paddingCharCount == $allowedValues[$i] &&
				substr( $secret, -( $allowedValues[$i] ) ) != str_repeat( $base32chars[32], $allowedValues[$i] ) ) {
				return false;
			}
		}
		$secret = str_replace( '=', '', $secret );
		$secret = str_split( $secret );
		$binaryString = '';
		for ( $i = 0; $i < count( $secret ); $i = $i + 8 ) {
			$x = '';
			if ( !in_array( $secret[$i], $base32chars ) ) {
				return false;
			}
			for ( $j = 0; $j < 8; ++$j ) {
				$x .= str_pad( base_convert( @$base32charsFlipped[@$secret[$i + $j]], 10, 2 ), 5, '0', STR_PAD_LEFT );
			}
			$eightBits = str_split( $x, 8 );
			for ( $z = 0; $z < count( $eightBits ); ++$z ) {
				$binaryString .= ( ( $y = chr( base_convert( $eightBits[$z], 2, 10 ) ) ) || ord( $y ) == 48 ) ? $y : '';
			}
		}

		return $binaryString;
	}

	/**
	 * A timing safe equals comparison
	 * more info here: http://blog.ircmaxell.com/2014/11/its-all-about-time.html.
	 *
	 * @param string $safeString The internal (safe) value to be checked
	 * @param string $userString The user submitted (unsafe) value
	 *
	 * @return bool True if the two strings are identical
	 */
	private static function timingSafeEquals( $safeString, $userString ) {
		if ( function_exists( 'hash_equals' ) ) {
			return hash_equals( $safeString, $userString );
		}
		$safeLen = strlen( $safeString );
		$userLen = strlen( $userString );

		if ( $userLen != $safeLen ) {
			return false;
		}

		$result = 0;

		for ( $i = 0; $i < $userLen; ++$i ) {
			$result |= ( ord( $safeString[$i] ) ^ ord( $userString[$i] ) );
		}

		// They are only identical strings if $result is exactly 0...
		return $result === 0;
	}

}

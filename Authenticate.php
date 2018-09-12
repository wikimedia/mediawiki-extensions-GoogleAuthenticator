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
 * @date: 9/7/18 / 3:08 PM
 * @author: Youri van den Bogert
 * @url: http://www.xl-knowledge.nl/
 */
namespace MediaWiki\Extensions\GoogleAuthenticator;

class Authenticate {

	const OPT_SECRET = 'GA_SECRET';
	const OPT_HAS_GA = 'GA_ENABLED';

	/**
	 * See if the given code valid
	 *
	 * @param $secret
	 * @param $code
	 * @return boolean
	 */
	public static function isValid($secret, $code) {
		return self::getAuth()->verifyCode( $secret, $code );
	}

	/**
	 * Generates the secret
	 * @param int $secretLength
	 * @return string
	 * @throws \Exception
	 */
	public static function createSecret($secretLength = 16) {
		return self::getAuth()->createSecret( $secretLength );
	}


	/**
	 * Returns the img url
	 *
	 * @return string
	 */
	public static function getQRImageURL( $secret ) {
		global $wgGAIssuer, $wgSitename, $wgUser;


		// Set issuer
		$issuer = str_replace('__SITENAME__', $wgSitename, $wgGAIssuer);

		// Return Google's QR URL
		return self::getAuth()->getQRCodeGoogleUrl(
			str_replace(' ', '-', $wgUser->getName() ),
			$secret,
			$issuer
		);
	}

	/**
	 * @return \PHPGangsta_GoogleAuthenticator
	 */
	private static function getAuth() {
		return new \PHPGangsta_GoogleAuthenticator();
	}

}
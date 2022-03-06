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
 * @date: 9/11/18 / 11:39 AM
 * @author: Youri van den Bogert
 * @url: http://www.xl-knowledge.nl/
 */

namespace MediaWiki\Extension\GoogleAuthenticator;

use MediaWiki\Auth\AuthenticationRequest;

class Google2FactorAuthenticationRequest extends AuthenticationRequest {

	/** @var string */
	public $token;

	/** @var bool */
	private $newlyGenerated = false;

	/** @var null|string */
	private $secret = null;

	/** @var array */
	private $rescueCodes = [];

	/**
	 * Google2FactorAuthenticationRequest constructor.
	 *
	 * @param string|null $secret
	 * @param bool $newlyGenerated
	 * @param array $rescueCodes
	 */
	public function __construct( $secret, $newlyGenerated = false, array $rescueCodes = [] ) {
		$this->newlyGenerated = $newlyGenerated;
		$this->secret = $secret;
		$this->rescueCodes = $rescueCodes;
	}

	/**
	 * @return array
	 * @see AuthenticationRequest::getFieldInfo()
	 */
	public function getFieldInfo() {
		$fields = [];

		if ( $this->newlyGenerated ) {

			// Secret code field
			$fields['secret'] = [
				'type' => 'null',
				'label' => wfMessage(
					'google2fa-secret-img',
					$this->getQRBase64( $this->secret ),
					$this->secret
				),
				'help' => '',
				'skippable' => true
			];

			// Rescue codes field
			$fields['rescue'] = [
				'type' => 'null',
				'label' => wfMessage( 'google2fa-rescue-codes', $this->rescueCodes[0],
					$this->rescueCodes[1], $this->rescueCodes[2] ),
				'help' => '',
				'skippable' => true
			];

		}

		// Token input field
		$fields['token'] = [
				'type' => 'string',
				'label' => wfMessage( 'google2fa-token-label' ),
				'help' => wfMessage( 'google2fa-token-help' ),
				'skippable' => false,
				'optional' => false
		];

		if ( !$this->newlyGenerated ) {

			// Token lost field
			$fields['tokenlost'] = [
				'type' => 'null',
				'label' => wfMessage( 'google2fa-token-lost', $this->username ),
				'help' => '',
				'skippable' => true
			];

		}

		return $fields;
	}

	/**
	 * Returns the base64 of the QR code
	 *
	 * @param string|null $secret
	 * @return string
	 * @throws \Exception
	 */
	private function getQRBase64( $secret ) {
		$qrCode = GoogleAuthenticator::getQRCode( $secret, $this->username );
		return base64_encode( $qrCode );
	}

}

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
 * @date: 9/12/18 / 5:59 PM
 * @author: Youri van den Bogert
 * @url: http://www.xl-knowledge.nl/
 */

namespace MediaWiki\Extensions\GoogleAuthenticator;

use MediaWiki\Logger\LoggerFactory;

class Google2FARecover extends \SpecialPage {

	const OPT_WAS_MAIL_SENT = 'Google2FA_Recover_mail_sent';

	public function __construct() {
		parent::__construct( 'Google2FARecover' );
	}

	public function execute( $par ) {
		$requestForUser = $this->getRequest()->getText( 'user', false );
		$user = ( $requestForUser ) ? \User::newFromName( $requestForUser ) : false;

		// Invalid user
		if ( !$requestForUser && !$user ) {
			$this->getOutput()->addWikiTextAsInterface( wfMessage( 'google2fa-invalid-user' ) );

		// User didn't verify his or her emailaddress
		} elseif ( $user->isEmailConfirmationPending() || !$user->isEmailConfirmed() ) {
			$this->getOutput()->addWikiTextAsInterface( wfMessage( 'google2fa-email-not-confirmed' ) );

		// Recover email was already sent
		} elseif ( $user->getOption( self::OPT_WAS_MAIL_SENT, false ) !== false ) {
			$this->getOutput()->addWikiTextAsInterface( wfMessage( 'google2fa-mail-already-sent' ) );

		// Sent recover codes
		} else {

			$body = wfMessage(
				'google2fa-mail-body',
				$user->getOption( Google2FactorSecondaryAuthenticationProvider::OPT_RESCUE_1 ),
				$user->getOption( Google2FactorSecondaryAuthenticationProvider::OPT_RESCUE_2 ),
				$user->getOption( Google2FactorSecondaryAuthenticationProvider::OPT_RESCUE_3 )
			);

			$wasMailedSuccesfully = $user->sendMail(
				wfMessage( 'google2fa-mail-title' )->text(),
				$body->text()
			);

			if ( !$wasMailedSuccesfully->isOK() ) {
				throw new \Exception( "Coudln't send email!" );
			} else {

				// Update mail sent var
				$user->setOption( self::OPT_WAS_MAIL_SENT, '1' );
				$user->saveSettings();

				// Output info
				$this->getOutput()->addWikiTextAsInterface( wfMessage( 'google2fa-mail-sent' ) );

				LoggerFactory::getInstance( 'Google2FA' )->info(
					'Sending recover email to {user}',
					[ 'user' => $user->getName() ]
				);

			}

			return true;

		}
	}
}

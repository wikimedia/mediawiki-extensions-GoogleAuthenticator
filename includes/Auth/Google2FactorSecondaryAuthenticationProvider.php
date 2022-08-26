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

use MediaWiki\Auth\AbstractSecondaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\MediaWikiServices;

class Google2FactorSecondaryAuthenticationProvider extends AbstractSecondaryAuthenticationProvider {

	/** @var int Maximum allowed of retries */
	const MAX_RETRIES = 4;

	/** @var string */
	const OPT_SECRET = 'Google2FA_Secret';

	/** @var string */
	const OPT_SECRET_SETUP = 'Google2FA_Secret_SetupComplete';

	/** @var string */
	const OPT_RESCUE_1 = 'Google2FA_SecretRescue1';

	/** @var string */
	const OPT_RESCUE_2 = 'Google2FA_SecretRescue2';

	/** @var string */
	const OPT_RESCUE_3 = 'Google2FA_SecretRescue3';

	/**
	 * @param string $action
	 * @param array $options
	 * @return array|\MediaWiki\Auth\AuthenticationRequest[]
	 */
	public function getAuthenticationRequests( $action, array $options ) {
		return [];
	}

	/**
	 * Begins the secondary authentication process. Generates new secrets
	 * for new requests
	 *
	 * @param \User $user
	 * @param array $reqs
	 * @return AuthenticationResponse
	 * @throws \Exception
	 */
	public function beginSecondaryAuthentication( $user, array $reqs ) {
		$userOptionsManager = MediaWikiServices::getInstance()->getUserOptionsManager();
		$secret = $userOptionsManager->getOption( $user, self::OPT_SECRET, false );
		$completedSetup = $userOptionsManager->getOption( $user, self::OPT_SECRET_SETUP, false );

		// If the setup was never completed, and secret was false, generate new secrets
		if ( !$completedSetup && $secret === false ) {
			// Generate a new secret
			$secret = $this->generateSecrets( $user );
			// Log action
			LoggerFactory::getInstance( 'Google2FA' )->info(
				'Generated new token for {user}',
				[ 'user' => $user->getName() ]
			);
		}

		// Set rescue codes
		$rescueCodes = [
			$userOptionsManager->getOption( $user, self::OPT_RESCUE_1 ),
			$userOptionsManager->getOption( $user, self::OPT_RESCUE_2 ),
			$userOptionsManager->getOption( $user, self::OPT_RESCUE_3 )
		];

		return AuthenticationResponse::newUI(
			[ new Google2FactorAuthenticationRequest( $secret, ( !$completedSetup ), $rescueCodes ) ],
			wfMessage( 'google2fa-info' )
		);
	}

	/**
	 * Validates the user's input
	 *
	 * @param User $user
	 * @param array $reqs
	 * @return AuthenticationResponse
	 * @throws \Exception
	 */
	public function continueSecondaryAuthentication( $user, array $reqs ) {
		$userOptionsManager = MediaWikiServices::getInstance()->getUserOptionsManager();
		// Fetch the secret
		$secret = $userOptionsManager->getOption( $user, self::OPT_SECRET, false );
		$secretSetup = $userOptionsManager->getOption( $user, self::OPT_SECRET_SETUP, false );

		// Fetch rescue options
		$rescueCodes = [
			$userOptionsManager->getOption( $user, self::OPT_RESCUE_1 ),
			$userOptionsManager->getOption( $user, self::OPT_RESCUE_3 ),
			$userOptionsManager->getOption( $user, self::OPT_RESCUE_2 ),
		];

		/** @var Google2FactorAuthenticationRequest $req */
		$req = AuthenticationRequest::getRequestByClass( $reqs, Google2FactorAuthenticationRequest::class );

		// If the user has given a rescue code, reset the OPT_SECRET_SETUP and show the form again
		if ( $req && in_array( $req->token, $rescueCodes ) ) {

			// Reset all the codes of the user
			$this->resetSecretCodes( $user );

			LoggerFactory::getInstance( 'Google2FA' )
				->info( 'Succesfully reset secret for {user}', [ 'user' => $user->getName() ] );

			// Return the 2 FA authentication process again
			return $this->beginSecondaryAuthentication( $user, $reqs );

		// Wrong token given upon new code
		} elseif ( $req && !GoogleAuthenticator::verifyCode( $secret, $req->token ) && !$secretSetup ) {

			LoggerFactory::getInstance( 'Google2FA' )->info(
				'{user} gave a wrong code in the setup process.',
				[ 'user' => $user->getName() ]
			);

			// Return the 2 FA authentication process again
			return $this->beginSecondaryAuthentication( $user, $reqs );

		// We have a valid session when the code has been verified succesfully
		} elseif ( $req && GoogleAuthenticator::verifyCode( $secret, $req->token ) ) {

			// The secret has been saved in to the DB and the given code was
			// validated. Save it to the DB
			if ( $userOptionsManager->getOption( $user, self::OPT_SECRET_SETUP, false ) === false ) {

				// Set option & save settings
				$userOptionsManager->setOption( $user, self::OPT_SECRET_SETUP, "1" );
				$userOptionsManager->saveOptions( $user );

				LoggerFactory::getInstance( 'Google2FA' )->info(
					'Succesfully validated new secret for {user}',
					[ 'user' => $user->getName() ]
				);

			}

			return AuthenticationResponse::newPass();

		// Invalid code given
		} elseif ( $req && !GoogleAuthenticator::verifyCode( $secret, $req->token ) ) {
			LoggerFactory::getInstance( 'Google2FA' )->info( 'Invalid token for {user}', [ 'user' => $user->getName() ] );
		}

		// Fetch the num of failures
		$failures = $this->manager->getAuthenticationSessionData( 'AuthFailures' );
		if ( $failures >= self::MAX_RETRIES ) {
			return AuthenticationResponse::newFail( wfMessage( 'google2fa-login-retry-limit' ) );
		}

		// Save num of failures
		$this->manager->setAuthenticationSessionData( 'AuthFailures', $failures + 1 );

		// Return the authentication request
		return AuthenticationResponse::newUI(
			[ new Google2FactorAuthenticationRequest( $secret ) ],
			wfMessage( 'google2fa-login-failure' ),
			'error'
		);
	}

	/**
	 * @param \User $user
	 * @param \User $creator
	 * @param array $reqs
	 * @return AuthenticationResponse
	 */
	public function beginSecondaryAccountCreation( $user, $creator, array $reqs ) {
		return AuthenticationResponse::newAbstain();
	}

	/**
	 * Generates the secrets for the given user and returns the main secret
	 *
	 * @param \User $user
	 * @return string
	 * @throws \Exception
	 */
	private function generateSecrets( $user ) {
		$mainSecret = GoogleAuthenticator::generateSecret();

		// Save secrets
		$user->setOption( self::OPT_SECRET, $mainSecret );
		$user->setOption( self::OPT_RESCUE_1, GoogleAuthenticator::generateSecret() );
		$user->setOption( self::OPT_RESCUE_2, GoogleAuthenticator::generateSecret() );
		$user->setOption( self::OPT_RESCUE_3, GoogleAuthenticator::generateSecret() );

		// Save user settings
		$user->saveSettings();

		// Return the first secret
		return $mainSecret;
	}

	/**
	 * Resets all the codes for the given user
	 *
	 * @param UserIdentity $user
	 * @param bool $resetMaster
	 * @return bool
	 */
	private function resetSecretCodes( $user, $resetMaster = true ) {
		$userOptionsManager = MediaWikiServices::getInstance()->getUserOptionsManager();
		$userOptionsManager->setOption( $user, self::OPT_SECRET_SETUP, false );

		// We might not always the master code
		if ( $resetMaster ) {
			$userOptionsManager->setOption( $user, self::OPT_SECRET, false );
		}

		// Reset rescue codes
		$userOptionsManager->setOption( $user, self::OPT_RESCUE_1, false );
		$userOptionsManager->setOption( $user, self::OPT_RESCUE_2, false );
		$userOptionsManager->setOption( $user, self::OPT_RESCUE_3, false );

		// Reset mail sent option
		$userOptionsManager->setOption( $user, Google2FARecover::OPT_WAS_MAIL_SENT, false );

		// Save settings
		$userOptionsManager->saveOptions( $user );

		return true;
	}

}

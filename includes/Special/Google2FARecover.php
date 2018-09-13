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

class Google2FARecover extends \SpecialPage {


	public function __construct() {
		parent::__construct( 'Google2FARecover' );
	}

	public function execute( $par ){

	}
}
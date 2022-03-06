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
namespace MediaWiki\Extension\GoogleAuthenticator;

class Hooks {

	/**
	 * @param \OutputPage $out
	 * @param \Skin $skin
	 */
	public static function onBeforePageDisplay( \OutputPage $out, \Skin $skin ) {
		// We only want to load the required javascript and CSS files if we are on the
		// login page. We do this to prevent users from loading images externally with using the
		// span.g2faqr script.
		if ( $out->getTitle()->getText() == wfMessage( 'login' )->text() ) {
			$out->addModules( "ext.Google2FA" );
		}
	}

}

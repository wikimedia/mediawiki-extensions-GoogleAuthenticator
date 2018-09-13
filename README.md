MediaWiki Google2Factor authentication extension
===
Version 1.0.0
 - Last update: 13 september 2018

This is the README file for the Google2Factor extension for MediaWiki
software. The extension is only useful if you've got a MediaWiki
installation; it can only be installed by the administrator of the site.

Minimum requirements
===
* MediaWiki 1.27+

Installation instructions
===
1. Clone this repository in your extensions directory of the MediaWiki installation
2. Edit your LocalSettings.php and, at the end of the file, add the following: `wfLoadExtension("GoogleAuthenticator")`
3. Enjoy your safety!

Custom variables
===
* `$wgGAIssuer` is set to $wgSitename as default. You can use this to set a different display name in the GoogleAuthenticator app on your phone.

Todo/Ideas
===
Todo: <nothing atm>

Ideas? Please, don't hesitate to contact me! 
  
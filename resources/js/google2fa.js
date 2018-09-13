( function ( mw ) {

	$('span.g2faqr').css({
		'display': 'block',
		'width': '200px',
		'height': '200px',
		'background': 'url("data:image/png;base64,'+ $('span.g2faqr').text() + '")',
		'text-indent': '-99999px'
	});

}( mediaWiki, jQuery ) );

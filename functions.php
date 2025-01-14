<?php
/**
 * Global WP-Auth0 functions.
 *
 * @package WP-Auth0
 *
 * @since 3.10.0
 */

/**
 * Generate a secure, random, URL-safe token.
 *
 * @since 4.0.0
 *
 * @return string
 */
function wp_auth0_generate_token() {
	$token = WP_Auth0_Nonce_Handler::get_instance()->generate_unique( 64 );
	return JWT::urlsafeB64Encode( $token );
}

/**
 * Return a stored option value.
 *
 * @since 3.10.0
 *
 * @param string $key - Settings key to get.
 * @param mixed  $default - Default value to return if not found.
 *
 * @return mixed
 */
function wp_auth0_get_option( $key, $default = null ) {
	return WP_Auth0_Options::Instance()->get( $key, $default );
}

/**
 * Determine if we're on the wp-login.php page and if the current action matches a given set.
 *
 * @since 3.11.0
 *
 * @param array $actions - An array of actions to check the current action against.
 *
 * @return bool
 */
function wp_auth0_is_current_login_action( array $actions ) {

	// Not on wp-login.php.
	if (
		( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' !== $GLOBALS['pagenow'] ) &&
		! function_exists( 'login_header' )
	) {
		return false;
	}

	$current_action = isset( $_REQUEST['action'] ) ? $_REQUEST['action'] : null;
	return in_array( $current_action, $actions );
}

/**
 * Generate a valid WordPress login override URL, if plugin settings allow.
 *
 * @param null $login_url - An existing URL to modify; default is wp-login.php.
 *
 * @return string
 */
function wp_auth0_login_override_url( $login_url = null ) {
	$wle = wp_auth0_get_option( 'wordpress_login_enabled' );
	if ( 'no' === $wle ) {
		return '';
	}

	$wle_code = '';
	if ( 'code' === $wle ) {
		$wle_code = wp_auth0_get_option( 'wle_code' );
	}

	$login_url = $login_url ?: wp_login_url();
	return add_query_arg( 'wle', $wle_code, $login_url );
}

/**
 * Can the core WP login form be shown?
 *
 * @return bool
 */
function wp_auth0_can_show_wp_login_form() {
	if ( ! WP_Auth0::ready() ) {
		return true;
	}

	if ( wp_auth0_is_current_login_action( [ 'resetpass', 'rp', 'validate_2fa', 'postpass' ] ) ) {
		return true;
	}

	if ( get_query_var( 'auth0_login_successful' ) ) {
		return true;
	}

	if ( ! isset( $_REQUEST['wle'] ) ) {
		return false;
	}

	$wle_setting = wp_auth0_get_option( 'wordpress_login_enabled' );
	if ( 'no' === $wle_setting ) {
		return false;
	}

	if ( in_array( $wle_setting, [ 'link', 'isset' ] ) ) {
		return true;
	}

	$wle_code = wp_auth0_get_option( 'wle_code' );
	if ( 'code' === $wle_setting && $wle_code === $_REQUEST['wle'] ) {
		return true;
	}

	return false;
}

if ( ! function_exists( 'get_auth0userinfo' ) ) {
	/**
	 * Get the Auth0 profile from the database, if one exists.
	 *
	 * @param string $auth0_user_id - Auth0 user ID to find.
	 *
	 * @return mixed
	 */
	//phpcs:ignore
	function get_auth0userinfo( $auth0_user_id ) {
		$profile = WP_Auth0_UsersRepo::get_meta( $auth0_user_id, 'auth0_obj' );
		return $profile ? WP_Auth0_Serializer::unserialize( $profile ) : false;
	}
}

if ( ! function_exists( 'get_currentauth0user' ) ) {
	/**
	 * Get all Auth0 data for the currently logged-in user.
	 *
	 * @return object
	 */
	//phpcs:ignore
	function get_currentauth0user() {
		return (object) [
			'auth0_obj'   => get_auth0userinfo( get_current_user_id() ),
			'last_update' => WP_Auth0_UsersRepo::get_meta( get_current_user_id(), 'last_update' ),
			'auth0_id'    => WP_Auth0_UsersRepo::get_meta( get_current_user_id(), 'auth0_id' ),
		];
	}
}

if ( ! function_exists( 'get_auth0_curatedBlogName' ) ) {
	/**
	 * Get the Auth0 application name from the current site name.
	 *
	 * @return mixed
	 */
	//phpcs:ignore
	function get_auth0_curatedBlogName() {

		$name = get_bloginfo( 'name' );

		// WordPress can have a blank site title, which will cause initial client creation to fail.
		if ( empty( $name ) ) {
			$name = wp_parse_url( home_url(), PHP_URL_HOST );
			$port = wp_parse_url( home_url(), PHP_URL_PORT );

			if ( $port ) {
				$name .= ':' . $port;
			}
		}

		$name = preg_replace( '/[^A-Za-z0-9 ]/', '', $name );
		$name = preg_replace( '/\s+/', ' ', $name );
		$name = str_replace( ' ', '-', $name );

		return $name;
	}
}

if ( ! function_exists( 'get_currentauth0userinfo' ) ) {
	/**
	 * Set the global $currentauth0_user and return the Auth0 data for the currently logged-in user.
	 *
	 * @return mixed
	 */
	//phpcs:ignore
	function get_currentauth0userinfo() {
		global $currentauth0_user;
		//phpcs:ignore
		$currentauth0_user = get_auth0userinfo( get_current_user_id() );
		return $currentauth0_user;
	}
}

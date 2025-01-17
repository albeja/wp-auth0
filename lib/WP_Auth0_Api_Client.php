<?php
/**
 * Contains Class WP_Auth0_Api_Client class.
 *
 * @package WP-Auth0
 *
 * @since 1.2.1
 */

/**
 * Class WP_Auth0_Api_Client
 */
class WP_Auth0_Api_Client {

	const DEFAULT_CLIENT_ALG = 'RS256';

	/**
	 * Reusable API information.
	 *
	 * @var array|null
	 */
	private static $connect_info = null;

	/**
	 * Generate the API endpoint with a provided domain.
	 *
	 * @since 3.5.0
	 *
	 * @param string $path - API path appended to the domain.
	 * @param string $domain - domain to use, blank uses default.
	 *
	 * @return string
	 */
	private static function get_endpoint( $path = '', $domain = '' ) {

		if ( empty( $domain ) ) {
			$a0_options = WP_Auth0_Options::Instance();
			$domain     = $a0_options->get( 'domain' );
		}

		if ( ! empty( $path[0] ) && '/' === $path[0] ) {
			$path = substr( $path, 1 );
		}

		return "https://{$domain}/{$path}";
	}

	/**
	 * Return basic connection information, or a specific value
	 *
	 * @since 3.5.0
	 *
	 * @param string $opt - specific option needed, returns all if blank.
	 *
	 * @return string|array
	 */
	public static function get_connect_info( $opt = '' ) {

		if ( is_null( self::$connect_info ) ) {
			$a0_options = WP_Auth0_Options::Instance();

			self::$connect_info = [
				'domain'                => $a0_options->get( 'domain' ),
				'client_id'             => $a0_options->get( 'client_id' ),
				'client_secret'         => $a0_options->get( 'client_secret' ),
				'client_secret_encoded' => $a0_options->get( 'client_secret_b64_encoded' ),
				'connection'            => $a0_options->get( 'db_connection_name' ),
				'app_token'             => null,
				'audience'              => self::get_endpoint( 'api/v2/' ),
			];
		}

		if ( empty( $opt ) ) {
			return self::$connect_info;
		} else {
			return ! empty( self::$connect_info[ $opt ] ) ? self::$connect_info[ $opt ] : '';
		}
	}

	/**
	 * Basic header components for an Auth0 API call.
	 *
	 * @since 3.5.0
	 *
	 * @param string $token - For Authorization header.
	 * @param string $content_type - For Content-Type header.
	 *
	 * @return array
	 */
	private static function get_headers( $token = '', $content_type = 'application/json' ) {

		$headers = WP_Auth0_Api_Abstract::get_info_headers();

		if ( ! empty( $token ) ) {
			$headers['Authorization'] = "Bearer {$token}";
		}

		if ( ! empty( $content_type ) ) {
			$headers['Content-Type'] = $content_type;
		}

		return $headers;
	}

	/**
	 * Create a new user for a database connection.
	 *
	 * @param string         $domain - Tenant domain for the Authentication API.
	 * @param array|stdClass $data - User data to send for signup.
	 *
	 * @return mixed
	 */
	public static function signup_user( $domain, $data ) {

		$endpoint = "https://$domain/dbconnections/signup";

		$headers = WP_Auth0_Api_Abstract::get_info_headers();

		$headers['content-type'] = 'application/json';

		$response = wp_remote_post(
			$endpoint,
			[
				'headers' => $headers,
				'body'    => json_encode( $data ),
			]
		);

		if ( $response instanceof WP_Error ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response );
			error_log( $response->get_error_message() );
			return false;
		}

		if ( $response['response']['code'] !== 200 ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response['body'] );
			error_log( $response['body'] );
			return false;
		}

		return json_decode( $response['body'] );
	}

	/**
	 * Scopes required by the WordPress application for the Management API.
	 *
	 * @return array
	 */
	public static function get_required_scopes() {
		return [
			'read:users',
			'update:users',
		];
	}

	/**
	 * Create a new Application for the WordPress site.
	 *
	 * @see https://auth0.com/docs/clients/client-settings/regular-web-app
	 * @see https://auth0.com/docs/api/management/v2#!/Clients/post_clients
	 *
	 * @param string $domain - Tenant domain for the Management API.
	 * @param string $app_token - Valid Management API token with create:clients scope.
	 * @param string $name - Name of the new Application.
	 *
	 * @return bool|object|array
	 */
	public static function create_client( $domain, $app_token, $name ) {

		$options = WP_Auth0_Options::Instance();

		$payload = [
			'name'                => $name,
			'app_type'            => 'regular_web',

			// Callback URLs for Auth Code and Hybrid/Implicit
			'callbacks'           => [
				$options->get_wp_auth0_url(),
			],

			// Web origins do not take into account the path
			'web_origins'         => $options->get_web_origins(),

			// Force SSL, will not work without it
			'cross_origin_loc'    => $options->get_cross_origin_loc(),
			'cross_origin_auth'   => true,

			// A set of URLs that are valid to redirect to after logout from Auth0
			'allowed_logout_urls' => [
				home_url(),
				wp_login_url(),
			],

			// Advanced > Grant Types
			'grant_types'         => self::get_client_grant_types(),

			// Advanced > OAuth > JsonWebToken Signature Algorithm
			'jwt_configuration'   => [
				'alg' => self::DEFAULT_CLIENT_ALG,
			],

			// "Use Auth0 to do Single Sign On"
			'sso'                 => true,

			// Advanced > OAuth > OIDC Conformant
			// https://auth0.com/docs/api-auth/intro#legacy-vs-new
			'oidc_conformant'     => true,
		];

		$response = wp_remote_post(
			self::get_endpoint( 'api/v2/clients', $domain ),
			[
				'headers' => self::get_headers( $app_token ),
				'body'    => json_encode( $payload ),
			]
		);

		if ( $response instanceof WP_Error ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response->get_error_message() );
			error_log( $response->get_error_message() );
			return false;
		}

		if ( $response['response']['code'] != 201 ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response['body'] );
			error_log( $response['body'] );
			return false;
		}

		return json_decode( $response['body'] );
	}


	/**
	 * Create a Client Grant for the Management API.
	 *
	 * @param string $app_token - Valid Management API token with create:client_grants scope.
	 * @param string $client_id - Client ID for the WordPress Application.
	 *
	 * @return array|bool|mixed|object
	 */
	public static function create_client_grant( $app_token, $client_id ) {

		$data = [
			'client_id' => $client_id,
			'audience'  => self::get_connect_info( 'audience' ),
			'scope'     => self::get_required_scopes(),
		];

		$response = wp_remote_post(
			self::get_endpoint( 'api/v2/client-grants' ),
			[
				'headers' => self::get_headers( $app_token ),
				'body'    => json_encode( $data ),
			]
		);

		if ( $response instanceof WP_Error ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response );
			error_log( $response->get_error_message() );
			return false;
		}

		if ( 409 === $response['response']['code'] ) {

			// Client grant from WP-created client to Management API already exists
			WP_Auth0_ErrorManager::insert_auth0_error(
				__METHOD__,
				sprintf(
					// translators: placeholders are machine names stored for this WP instance and must be included.
					__( 'A client grant for %1$s to %2$s already exists. Make sure this grant at least includes %3$s.', 'wp-auth0' ),
					self::get_connect_info( 'client_id' ),
					self::get_connect_info( 'audience' ),
					implode( ', ', self::get_required_scopes() )
				)
			);

			return json_decode( $response['body'] );

		} elseif ( $response['response']['code'] != 201 ) {

			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response['body'] );
			error_log( $response['body'] );
			return false;
		}

		return json_decode( $response['body'] );
	}

	/**
	 * Create a database Connection.
	 *
	 * @param string         $domain - Tenant domain for the Management API.
	 * @param string         $app_token - Valid Management API token with create:connections scope.
	 * @param array|stdClass $payload - Create Connection data to send.
	 *
	 * @return mixed
	 */
	public static function create_connection( $domain, $app_token, $payload ) {
		$endpoint = "https://$domain/api/v2/connections";

		$headers = WP_Auth0_Api_Abstract::get_info_headers();

		$headers['Authorization'] = "Bearer $app_token";
		$headers['content-type']  = 'application/json';

		$response = wp_remote_post(
			$endpoint,
			[
				'method'  => 'POST',
				'headers' => $headers,
				'body'    => json_encode( $payload ),
			]
		);

		if ( $response instanceof WP_Error ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response );
			error_log( $response->get_error_message() );
			return false;
		}

		if ( $response['response']['code'] != 201 ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response['body'] );
			error_log( $response['body'] );
			return false;
		}

		return json_decode( $response['body'] );
	}

	/**
	 * Find a database Connection.
	 *
	 * @param string      $domain - Tenant domain for the Management API.
	 * @param string      $app_token - Valid Management API token with read:connections scope.
	 * @param string|null $strategy - Connection strategy to find.
	 *
	 * @return array|bool|mixed|object
	 */
	public static function search_connection( $domain, $app_token, $strategy = null ) {
		$endpoint = "https://$domain/api/v2/connections";

		if ( $strategy ) {
			$endpoint .= "?strategy=$strategy";
		}

		$headers = WP_Auth0_Api_Abstract::get_info_headers();

		$headers['Authorization'] = "Bearer $app_token";

		$response = wp_remote_get(
			$endpoint,
			[
				'headers' => $headers,
			]
		);

		if ( $response instanceof WP_Error ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response );
			error_log( $response->get_error_message() );
			return false;
		}

		if ( $response['response']['code'] != 200 ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response['body'] );
			error_log( $response['body'] );
			return false;
		}

		if ( $response['response']['code'] >= 300 ) {
			return false;
		}

		return json_decode( $response['body'] );
	}

	/**
	 * Update a Connection via the Management API.
	 * Note: $payload must be a complete settings object, not just the property to change.
	 *
	 * @param string   $domain - Tenant domain for the Management API.
	 * @param string   $app_token - Valid Management API token with update:connections scope.
	 * @param string   $id - DB Connection ID.
	 * @param stdClass $payload - DB Connection settings, will override existing.
	 *
	 * @return bool|object
	 */
	public static function update_connection( $domain, $app_token, $id, $payload ) {
		$endpoint = "https://$domain/api/v2/connections/$id";

		$headers = WP_Auth0_Api_Abstract::get_info_headers();

		$headers['Authorization'] = "Bearer $app_token";
		$headers['content-type']  = 'application/json';

		unset( $payload->name );
		unset( $payload->strategy );
		unset( $payload->id );

		if ( ! empty( $payload->enabled_clients ) ) {
			$payload->enabled_clients = array_values( $payload->enabled_clients );
		}

		$response = wp_remote_post(
			$endpoint,
			[
				'method'  => 'PATCH',
				'headers' => $headers,
				'body'    => json_encode( $payload ),
			]
		);

		if ( $response instanceof WP_Error ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response );
			error_log( $response->get_error_message() );
			return false;
		}

		if ( $response['response']['code'] != 200 ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response['body'] );
			error_log( $response['body'] );
			return false;
		}

		if ( $response['response']['code'] >= 300 ) {
			return false;
		}

		return json_decode( $response['body'] );
	}

	/**
	 * Return the Management API scopes needed for install.
	 *
	 * @return array
	 */
	public static function ConsentRequiredScopes() {
		return [
			'create:clients',
			'create:client_grants',
			'update:connections',
			'create:connections',
			'read:connections',
			'read:users',
			'update:users',
		];
	}

	/**
	 * Convert a certificate to PEM format.
	 *
	 * @param string $cert - Certificate, like from .well-known/jwks.json.
	 *
	 * @return string
	 */
	protected static function convertCertToPem( $cert ) {
		return '-----BEGIN CERTIFICATE-----' . PHP_EOL
			   . chunk_split( $cert, 64, PHP_EOL )
			   . '-----END CERTIFICATE-----' . PHP_EOL;
	}

	/**
	 * Get and cache a JWKS.
	 *
	 * @param string $domain - Issuer domain.
	 *
	 * @return array|bool|mixed
	 */
	public static function JWKfetch( $domain ) {

		$a0_options = WP_Auth0_Options::Instance();

		$endpoint = "https://$domain/.well-known/jwks.json";

		if ( false === ( $secret = get_transient( WPA0_JWKS_CACHE_TRANSIENT_NAME ) ) ) {

			$secret = [];

			$response = wp_remote_get( $endpoint, [] );

			if ( $response instanceof WP_Error ) {
				WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response );
				error_log( $response->get_error_message() );
				return false;
			}

			if ( $response['response']['code'] != 200 ) {
				WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $response['body'] );
				error_log( $response['body'] );
				return false;
			}

			if ( $response['response']['code'] >= 300 ) {
				return false;
			}

			$jwks = json_decode( $response['body'], true );

			foreach ( $jwks['keys'] as $key ) {
				$secret[ $key['kid'] ] = self::convertCertToPem( $key['x5c'][0] );
			}

			if ( $cache_expiration = $a0_options->get( 'cache_expiration' ) ) {
				set_transient( WPA0_JWKS_CACHE_TRANSIENT_NAME, $secret, $cache_expiration * MINUTE_IN_SECONDS );
			}
		}

		return $secret;
	}

	/**
	 * Return the grant types needed for new clients.
	 *
	 * @return array
	 */
	public static function get_client_grant_types() {

		return [
			'authorization_code',
			'implicit',
			'refresh_token',
			'client_credentials',
		];
	}
}

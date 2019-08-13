<?php
/**
 * Contains WP_Auth0_Id_Token_Validator.
 *
 * @package WP-Auth0
 *
 * @since 3.11.0
 */

/**
 * Class WP_Auth0_Id_Token_Validator.
 * Wrapper around JWT::decode() to do additional checks and enforce defaults.
 */
class WP_Auth0_Id_Token_Validator {

	/**
	 * ID token to decode.
	 *
	 * @var string
	 */
	protected $id_token;

	/**
	 * Key to use to verify the signature.
	 *
	 * @var bool|string
	 */
	protected $key;

	/**
	 * ID token algorithm.
	 *
	 * @var string
	 */
	protected $algorithm;

	/**
	 * ID token issuer to check.
	 *
	 * @var string
	 */
	protected $issuer;

	/**
	 * ID token audience to check.
	 *
	 * @var string
	 */
	protected $audience;

	/**
	 * WP_Auth0_Id_Token_Validator constructor.
	 *
	 * @param string           $id_token  ID token to verify and decode.
	 * @param WP_Auth0_Options $opts WP_Auth0_Options instance.
	 */
	public function __construct( $id_token, WP_Auth0_Options $opts ) {
		$this->id_token = $id_token;

		$this->key       = $opts->get_client_secret_as_key();
		$this->algorithm = $opts->get_client_signing_algorithm();
		$this->issuer    = 'https://' . $opts->get_auth_domain() . '/';
		$this->audience  = $opts->get( 'client_id' );

		JWT::$leeway = absint( apply_filters( 'auth0_jwt_leeway', \JWT::$leeway ) );
	}

	/**
	 * Decodes a JWT string into a PHP object.
	 *
	 * @param bool     $validate_nonce Validate the ID token nonce.
	 * @param int|null $max_age Maximum age of the authentication request, passed to auth endpoint.
	 *
	 * @return object
	 *
	 * @throws WP_Auth0_InvalidIdTokenException Provided JWT was invalid.
	 */
	public function decode( $validate_nonce = false, $max_age = null ) {

		try {
			$payload = JWT::decode( $this->id_token, $this->key, [ $this->algorithm ] );
		} catch ( Exception $e ) {
			throw new WP_Auth0_InvalidIdTokenException( $e->getMessage() );
		}

		// Check if the token sub is present.
		if ( empty( $payload->sub ) ) {
			throw new WP_Auth0_InvalidIdTokenException( __( 'Missing token sub', 'wp-auth0' ) );
		}

		// Check if the token issuer is valid.
		if ( ! isset( $payload->iss ) || $payload->iss !== $this->issuer ) {
			throw new WP_Auth0_InvalidIdTokenException( __( 'Invalid token iss', 'wp-auth0' ) );
		}

		// Check if the token audience is valid.
		$aud_array = null;
		if ( isset( $payload->aud ) ) {
			$aud_array = is_array( $payload->aud ) ? $payload->aud : [ $payload->aud ];
		}
		if ( ! $aud_array || ! in_array( $this->audience, $aud_array ) ) {
			throw new WP_Auth0_InvalidIdTokenException( __( 'Invalid token aud', 'wp-auth0' ) );
		}

		// Check if the azp is valid if we have multiple audiences.
		if ( count( $aud_array ) > 1 && ( empty( $payload->azp ) || ! in_array( $payload->azp, $aud_array ) ) ) {
			throw new WP_Auth0_InvalidIdTokenException( __( 'Invalid token azp', 'wp-auth0' ) );
		}

		// Check the auth_time of the token.
		if ( $max_age && ( empty( $payload->auth_time ) || time() >= ( $payload->auth_time + $max_age ) ) ) {
			throw new WP_Auth0_InvalidIdTokenException( __( 'Invalid token auth_time', 'wp-auth0' ) );
		}

		// Check if the token nonce is valid.
		$token_nonce = isset( $payload->nonce ) ? $payload->nonce : null;
		if ( $validate_nonce && ! WP_Auth0_Nonce_Handler::get_instance()->validate( $token_nonce ) ) {
			throw new WP_Auth0_InvalidIdTokenException( __( 'Invalid token nonce', 'wp-auth0' ) );
		}

		return $payload;
	}
}

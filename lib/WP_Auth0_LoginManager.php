<?php
/**
 * WP_Auth0_LoginManager class
 *
 * @package WordPress
 * @subpackage WP-Auth0
 * @since 2.0.0
 */

/**
 * Handles login callbacks and auto-login redirecting
 *
 * @since 2.0.0
 */
class WP_Auth0_LoginManager {

	/**
	 * Instance of WP_Auth0_Options.
	 *
	 * @var null|WP_Auth0_Options
	 */
	protected $a0_options;

	/**
	 * User strategy to use.
	 *
	 * @var WP_Auth0_UsersRepo
	 */
	protected $users_repo;

	/**
	 * WP_Auth0_LoginManager constructor.
	 *
	 * @param WP_Auth0_UsersRepo    $users_repo - see member variable doc comment.
	 * @param WP_Auth0_Options|null $a0_options - see member variable doc comment.
	 */
	public function __construct( WP_Auth0_UsersRepo $users_repo, WP_Auth0_Options $a0_options ) {
		$this->users_repo = $users_repo;
		$this->a0_options = $a0_options;
	}

	/**
	 * Redirect logged-in users from wp-login.php.
	 * Redirect to Universal Login Page under certain conditions and if the option is turned on.
	 *
	 * @return bool
	 */
	public function login_auto() {

		// Do not redirect anywhere if this is a logout action.
		if ( wp_auth0_is_current_login_action( [ 'logout' ] ) ) {
			return false;
		}

		// Do not redirect login page override.
		if ( wp_auth0_can_show_wp_login_form() ) {
			return false;
		}

		// If the user has a WP session, determine where they should end up and redirect.
		if ( is_user_logged_in() ) {
			$login_redirect = empty( $_REQUEST['redirect_to'] ) ?
				$this->a0_options->get( 'default_login_redirection' ) :
				filter_var( $_REQUEST['redirect_to'], FILTER_SANITIZE_URL );

			// Add a cache buster to avoid an infinite redirect loop on pages that check for auth.
			$login_redirect = add_query_arg( time(), '', $login_redirect );
			wp_safe_redirect( $login_redirect );
			exit;
		}

		// Do not use the ULP if the setting is off or if the plugin is not configured.
		if ( ! $this->a0_options->get( 'auto_login', false ) ) {
			return false;
		}

		$connection  = apply_filters( 'auth0_get_auto_login_connection', $this->a0_options->get( 'auto_login_method' ) );
		$auth_params = self::get_authorize_params( $connection );

		WP_Auth0_State_Handler::get_instance()->set_cookie( $auth_params['state'] );

		if ( isset( $auth_params['nonce'] ) ) {
			WP_Auth0_Nonce_Handler::get_instance()->set_cookie();
		}

		$auth_url = self::build_authorize_url( $auth_params );
		wp_redirect( $auth_url );
		exit;
	}

	/**
	 * Process an incoming successful login from Auth0, aka login callback.
	 * Auth0 must be configured and 'auth0' URL parameter not empty.
	 * Handles errors and state validation
	 */
	public function init_auth0() {

		set_query_var( 'auth0_login_successful', false );

		// Not an Auth0 login process or settings are not configured to allow logins.
		$cb_type = $this->query_vars( 'auth0' );
		if ( ! $cb_type || ! WP_Auth0::ready() ) {
			return false;
		}

		// Catch any incoming errors and stop the login process.
		// See https://auth0.com/docs/libraries/error-messages for more info.
		if ( ! empty( $_REQUEST['error'] ) || ! empty( $_REQUEST['error_description'] ) ) {
			$error_msg  = sanitize_text_field( rawurldecode( $_REQUEST['error_description'] ) );
			$error_code = sanitize_text_field( rawurldecode( $_REQUEST['error'] ) );
			$this->die_on_login( $error_msg, $error_code );
		}

		// No need to process a login if the user is already logged in and there is no error.
		if ( is_user_logged_in() ) {
			wp_redirect( $this->a0_options->get( 'default_login_redirection' ) );
			exit;
		}

		// Check for valid state value returned from Auth0.
		$cb_req = 'implicit' === $cb_type ? $_POST : $_GET;
		if ( empty( $cb_req['state'] ) || ! WP_Auth0_State_Handler::get_instance()->validate( $cb_req['state'] ) ) {
			$this->die_on_login( __( 'Invalid state', 'wp-auth0' ) );
		}

		try {
			if ( $cb_type === 'implicit' ) {
				$this->implicit_login();
			} else {
				$this->redirect_login();
			}
		} catch ( WP_Auth0_LoginFlowValidationException $e ) {

			// Errors encountered during the OAuth login flow.
			$this->die_on_login( $e->getMessage(), $e->getCode() );
		} catch ( WP_Auth0_BeforeLoginException $e ) {

			// Errors encountered during the WordPress login flow.
			$this->die_on_login( $e->getMessage(), $e->getCode() );
		} catch ( WP_Auth0_InvalidIdTokenException $e ) {
			$code            = 'invalid_id_token';
			$display_message = __( 'Invalid ID token', 'wp-auth0' );
			WP_Auth0_ErrorManager::insert_auth0_error(
				__METHOD__ . ' L:' . __LINE__,
				new WP_Error( $code, $display_message . ': ' . $e->getMessage() )
			);
			$this->die_on_login( $display_message, $code );
		}
	}

	/**
	 * Main login flow using the Authorization Code Grant.
	 *
	 * @throws WP_Auth0_LoginFlowValidationException - OAuth login flow errors.
	 * @throws WP_Auth0_BeforeLoginException - Errors encountered during the auth0_before_login action.
	 * @throws WP_Auth0_InvalidIdTokenException If the ID token does not validate.
	 *
	 * @link https://auth0.com/docs/api-auth/tutorials/authorization-code-grant
	 */
	public function redirect_login() {

		// Exchange authorization code for tokens.
		$exchange_api       = new WP_Auth0_Api_Exchange_Code( $this->a0_options, $this->a0_options->get_auth_domain() );
		$exchange_resp_body = $exchange_api->call( $this->query_vars( 'code' ) );

		if ( ! $exchange_resp_body ) {
			throw new WP_Auth0_LoginFlowValidationException( __( 'Error exchanging code', 'wp-auth0' ) );
		}

		$data = json_decode( $exchange_resp_body );

		$access_token  = isset( $data->access_token ) ? $data->access_token : null;
		$id_token      = $data->id_token;
		$refresh_token = isset( $data->refresh_token ) ? $data->refresh_token : null;

		// Decode the incoming ID token for the Auth0 user.
		$jwt_verifier  = new WP_Auth0_Id_Token_Validator( $id_token, $this->a0_options );
		$decoded_token = $jwt_verifier->decode();

		// Attempt to authenticate with the Management API, if allowed.
		$userinfo = null;
		if ( apply_filters( 'auth0_use_management_api_for_userinfo', true ) ) {
			$cc_api        = new WP_Auth0_Api_Client_Credentials( $this->a0_options );
			$get_user_api  = new WP_Auth0_Api_Get_User( $this->a0_options, $cc_api );
			$get_user_resp = $get_user_api->call( $decoded_token->sub );
			$userinfo      = ! empty( $get_user_resp ) ? json_decode( $get_user_resp ) : null;
		}

		// Management API call failed, fallback to ID token.
		if ( ! $userinfo ) {
			$userinfo = $this->clean_id_token( $decoded_token );
		}

		// Populate sub property, if not provided.
		if ( ! isset( $userinfo->sub ) ) {
			$userinfo->sub = $userinfo->user_id;
		}

		if ( $this->login_user( $userinfo, $id_token, $access_token, $refresh_token ) ) {
			$state_decoded = $this->get_state();
			if ( ! empty( $state_decoded->interim ) ) {
				include WPA0_PLUGIN_DIR . 'templates/login-interim.php';
			} else {
				if ( ! empty( $state_decoded->redirect_to ) && wp_login_url() !== $state_decoded->redirect_to ) {
					$redirect_url = $state_decoded->redirect_to;
				} else {
					$redirect_url = $this->a0_options->get( 'default_login_redirection' );
				}
				wp_safe_redirect( $redirect_url );
			}
			exit();
		}
	}

	/**
	 * Secondary login flow, Implicit Grant.
	 * Application type must be set to "Single Page App" to use this flow.
	 *
	 * @throws WP_Auth0_LoginFlowValidationException - OAuth login flow errors.
	 * @throws WP_Auth0_BeforeLoginException - Errors encountered during the auth0_before_login action.
	 * @throws WP_Auth0_InvalidIdTokenException - If the ID token does not validate.
	 *
	 * @link https://auth0.com/docs/api-auth/tutorials/implicit-grant
	 */
	public function implicit_login() {

		if ( empty( $_POST['id_token'] ) && empty( $_POST['token'] ) ) {
			throw new WP_Auth0_LoginFlowValidationException( __( 'No ID token found', 'wp-auth0' ) );
		}

		// Posted from the login page to the callback URL.
		$id_token_param = ! empty( $_POST['id_token'] ) ? $_POST['id_token'] : $_POST['token'];
		$id_token       = sanitize_text_field( wp_unslash( $id_token_param ) );

		$jwt_verifier  = new WP_Auth0_Id_Token_Validator( $id_token, $this->a0_options );
		$decoded_token = $jwt_verifier->decode( true );
		$decoded_token = $this->clean_id_token( $decoded_token );

		if ( $this->login_user( $decoded_token, $id_token ) ) {

			// Validated above in $this->init_auth0().
			$state_decoded = $this->get_state();

			if ( ! empty( $state_decoded->interim ) ) {
				include WPA0_PLUGIN_DIR . 'templates/login-interim.php';
			} else {
				$redirect_to = ! empty( $state_decoded->redirect_to ) ? $state_decoded->redirect_to : null;
				if ( ! $redirect_to || wp_login_url() === $redirect_to ) {
					$redirect_to = $this->a0_options->get( 'default_login_redirection' );
				}
				wp_safe_redirect( $redirect_to );
			}
			exit;
		}
	}

	/**
	 * Attempts to log the user in and create a new user, if possible/needed.
	 *
	 * @param object      $userinfo - Auth0 profile of the user.
	 * @param null|string $id_token - user's ID token if returned from Auth0.
	 * @param null|string $access_token - user's access token if returned from Auth0.
	 * @param null|string $refresh_token - user's refresh token if returned from Auth0.
	 *
	 * @return bool
	 *
	 * @throws WP_Auth0_LoginFlowValidationException - OAuth login flow errors.
	 * @throws WP_Auth0_BeforeLoginException - Errors encountered during the auth0_before_login action.
	 */
	public function login_user( $userinfo, $id_token = null, $access_token = null, $refresh_token = null ) {
		$auth0_sub        = $userinfo->sub;
		list( $strategy ) = explode( '|', $auth0_sub );

		// Check that the user has a verified email, if required.
		if (
			// Admin settings enforce verified email.
			$this->a0_options->get( 'requires_verified_email' ) &&
			// Strategy for the user is not skipped.
			! $this->a0_options->strategy_skips_verified_email( $strategy )
		) {

			// Email address is empty so cannot proceed.
			if ( empty( $userinfo->email ) ) {
				throw new WP_Auth0_LoginFlowValidationException(
					__( 'This account does not have an email associated, as required by your site administrator.', 'wp-auth0' )
				);
			}

			// Die with an action to re-send email verification.
			if ( empty( $userinfo->email_verified ) ) {
				WP_Auth0_Email_Verification::render_die( $userinfo );
			}
		}

		// See if there is a user linked to the same Auth0 user_id.
		if ( isset( $userinfo->identities ) ) {
			foreach ( $userinfo->identities as $identity ) {
				$user = $this->users_repo->find_auth0_user( "{$identity->provider}|{$identity->user_id}" );
				if ( $user ) {
					break;
				}
			}
		} else {
			$user = $this->users_repo->find_auth0_user( $auth0_sub );
		}

		$user = apply_filters( 'auth0_get_wp_user', $user, $userinfo );

		if ( ! is_null( $user ) ) {
			// User exists so log them in.
			if ( isset( $userinfo->email ) && $user->data->user_email !== $userinfo->email ) {
				$description = $user->data->description;
				if ( empty( $description ) ) {
					if ( isset( $userinfo->headline ) ) {
						$description = $userinfo->headline;
					}
					if ( isset( $userinfo->description ) ) {
						$description = $userinfo->description;
					}
					if ( isset( $userinfo->bio ) ) {
						$description = $userinfo->bio;
					}
					if ( isset( $userinfo->about ) ) {
						$description = $userinfo->about;
					}
				}

				wp_update_user(
					(object) [
						'ID'          => $user->data->ID,
						'user_email'  => $userinfo->email,
						'description' => $description,
					]
				);
			}

			$this->users_repo->update_auth0_object( $user->data->ID, $userinfo );
			$user = apply_filters( 'auth0_get_wp_user', $user, $userinfo );
			$this->do_login( $user, $userinfo, false, $id_token, $access_token, $refresh_token );
			return true;
		} else {

			try {

				$creator = new WP_Auth0_UsersRepo( $this->a0_options );
				$user_id = $creator->create( $userinfo, $id_token, $access_token );
				$user    = get_user_by( 'id', $user_id );
				$this->do_login( $user, $userinfo, true, $id_token, $access_token, $refresh_token );
			} catch ( WP_Auth0_CouldNotCreateUserException $e ) {

				throw new WP_Auth0_LoginFlowValidationException( $e->getMessage() );
			} catch ( WP_Auth0_RegistrationNotEnabledException $e ) {

				$msg = __(
					'Could not create user. The registration process is not available. Please contact your site’s administrator.',
					'wp-auth0'
				);
				throw new WP_Auth0_LoginFlowValidationException( $msg );
			} catch ( WP_Auth0_EmailNotVerifiedException $e ) {

				WP_Auth0_Email_Verification::render_die( $e->userinfo );
			}
			return true;
		}
	}

	/**
	 * Does all actions required to log the user in to WordPress, invoking hooks as necessary
	 *
	 * @param object      $user - the WP user object, such as returned by get_user_by().
	 * @param object      $userinfo - the Auth0 profile of the user.
	 * @param bool        $is_new - `true` if the user was created in the WordPress database, `false` if not.
	 * @param null|string $id_token - user's ID token if returned from Auth0, otherwise null.
	 * @param null|string $access_token - user's access token if returned from Auth0, otherwise null.
	 * @param null|string $refresh_token - user's refresh token if returned from Auth0, otherwise null.
	 *
	 * @throws WP_Auth0_BeforeLoginException - Errors encountered during the auth0_before_login action.
	 */
	private function do_login( $user, $userinfo, $is_new, $id_token, $access_token, $refresh_token ) {
		$remember_users_session = $this->a0_options->get( 'remember_users_session' );

		try {
			do_action( 'auth0_before_login', $user );
		} catch ( Exception $e ) {
			throw new WP_Auth0_BeforeLoginException( $e->getMessage() );
		}

		set_query_var( 'auth0_login_successful', true );

		$secure_cookie = is_ssl();

		// See wp_signon() for documentation on this filter.
		$secure_cookie = apply_filters(
			'secure_signon_cookie',
			$secure_cookie,
			[
				'user_login'    => $user->user_login,
				'user_password' => null,
				'remember'      => $remember_users_session,
			]
		);

		wp_set_auth_cookie( $user->ID, $remember_users_session, $secure_cookie );
		do_action( 'wp_login', $user->user_login, $user );
		do_action( 'auth0_user_login', $user->ID, $userinfo, $is_new, $id_token, $access_token, $refresh_token );
	}

	/**
	 * Complete the logout process based on settings.
	 * Hooked to `wp_logout` action.
	 * IMPORTANT: Internal callback use only, do not call this function directly!
	 *
	 * @see WP_Auth0_LoginManager::init()
	 *
	 * @link https://codex.wordpress.org/Plugin_API/Action_Reference/wp_logout
	 */
	public function logout() {
		if ( ! WP_Auth0::ready() ) {
			return;
		}

		// If SLO is in use, redirect to Auth0 to logout there as well.
		if ( $this->a0_options->get( 'singlelogout' ) ) {
			$return_to    = apply_filters( 'auth0_slo_return_to', home_url() );
			$redirect_url = $this->auth0_logout_url( $return_to );
			$redirect_url = apply_filters( 'auth0_logout_url', $redirect_url );
			wp_redirect( $redirect_url );
			exit;
		}

		// If auto-login is in use, cannot redirect back to login page.
		if ( $this->a0_options->get( 'auto_login' ) ) {
			wp_redirect( home_url() );
			exit;
		}
	}

	/**
	 * Get and filter the scope used for access and ID tokens.
	 *
	 * @param string $context - how the scopes are being used.
	 *
	 * @return string
	 */
	public static function get_userinfo_scope( $context = '' ) {
		$default_scope  = [ 'openid', 'email', 'profile' ];
		$filtered_scope = apply_filters( 'auth0_auth_scope', $default_scope, $context );
		return implode( ' ', $filtered_scope );
	}

	/**
	 * Get authorize URL parameters for handling Universal Login Page redirects.
	 *
	 * @param null|string $connection - a specific connection to use; pass null to use all enabled connections.
	 * @param null|string $redirect_to - URL to redirect upon successful authentication.
	 *
	 * @return array
	 */
	public static function get_authorize_params( $connection = null, $redirect_to = null ) {
		$opts         = WP_Auth0_Options::Instance();
		$lock_options = new WP_Auth0_Lock10_Options();
		$is_implicit  = (bool) $opts->get( 'auth0_implicit_workflow', false );
		$nonce        = WP_Auth0_Nonce_Handler::get_instance()->get_unique();

		$params = [
			'client_id'     => $opts->get( 'client_id' ),
			'scope'         => self::get_userinfo_scope( 'authorize_url' ),
			'response_type' => $is_implicit ? 'id_token' : 'code',
			'response_mode' => $is_implicit ? 'form_post' : 'query',
			'redirect_uri'  => $is_implicit ? $lock_options->get_implicit_callback_url() : $opts->get_wp_auth0_url(),
		];

		if ( $is_implicit ) {
			$params['nonce'] = $nonce;
		}

		if ( ! empty( $connection ) ) {
			$params['connection'] = $connection;
		}

		// Where should the user be redirected after logging in?
		if ( empty( $redirect_to ) ) {
			$redirect_to = empty( $_GET['redirect_to'] )
				? $opts->get( 'default_login_redirection' )
				: $_GET['redirect_to'];
		}

		$filtered_params = apply_filters( 'auth0_authorize_url_params', $params, $connection, $redirect_to );

		// State parameter, checked during login callback.
		if ( empty( $filtered_params['state'] ) ) {
			$state                    = [
				'interim'     => false,
				'nonce'       => WP_Auth0_State_Handler::get_instance()->get_unique(),
				'redirect_to' => filter_var( $redirect_to, FILTER_SANITIZE_URL ),
			];
			$filtered_state           = apply_filters( 'auth0_authorize_state', $state, $filtered_params );
			$filtered_params['state'] = base64_encode( json_encode( $filtered_state ) );
		}

		return $filtered_params;
	}

	/**
	 * Build a link to the tenant's authorize page.
	 *
	 * @param array $params - URL parameters to append.
	 *
	 * @return string
	 */
	public static function build_authorize_url( array $params = [] ) {
		$auth_url = 'https://' . WP_Auth0_Options::Instance()->get_auth_domain() . '/authorize';
		$auth_url = add_query_arg( array_map( 'rawurlencode', $params ), $auth_url );
		return apply_filters( 'auth0_authorize_url', $auth_url, $params );
	}

	/**
	 * Get a value from query_vars or request global.
	 *
	 * @param string $key - query var key to return.
	 *
	 * @return string|null
	 */
	protected function query_vars( $key ) {
		global $wp_query;
		if ( isset( $wp_query->query_vars[ $key ] ) ) {
			return $wp_query->query_vars[ $key ];
		}
		if ( isset( $_REQUEST[ $key ] ) ) {
			return $_REQUEST[ $key ];
		}
		return null;
	}

	/**
	 * Get the state value returned from Auth0 during login processing.
	 *
	 * @return string|object|null
	 */
	protected function get_state() {
		$state_val = rawurldecode( $_REQUEST['state'] );
		$state_val = base64_decode( $state_val );
		$state_val = json_decode( $state_val );
		return $state_val;
	}

	/**
	 * Die during login process with a message
	 *
	 * @param string     $msg - translated error message to display.
	 * @param string|int $code - error code, if given.
	 */
	protected function die_on_login( $msg = '', $code = 0 ) {

		// Log the user out completely.
		wp_destroy_current_session();
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );

		$html = sprintf(
			'%s: %s [%s: %s]<br><br><a href="%s">%s</a>',
			__( 'There was a problem with your log in', 'wp-auth0' ),
			! empty( $msg )
				? sanitize_text_field( $msg )
				: __( 'Please see the site administrator', 'wp-auth0' ),
			__( 'error code', 'wp-auth0' ),
			$code ? sanitize_text_field( $code ) : __( 'unknown', 'wp-auth0' ),
			$this->auth0_logout_url( wp_login_url() ),
			__( '← Login', 'wp-auth0' )
		);

		$html = apply_filters( 'auth0_die_on_login_output', $html, $msg, $code, false );
		wp_die( $html );
	}

	/**
	 * Remove unnecessary ID token properties.
	 *
	 * @param stdClass $id_token_obj - ID token object to clean.
	 *
	 * @return stdClass
	 *
	 * @codeCoverageIgnore - Private method
	 */
	private function clean_id_token( $id_token_obj ) {
		foreach ( [ 'iss', 'aud', 'iat', 'exp', 'nonce' ] as $attr ) {
			unset( $id_token_obj->$attr );
		}
		if ( ! isset( $id_token_obj->user_id ) && isset( $id_token_obj->sub ) ) {
			$id_token_obj->user_id = $id_token_obj->sub;
		} elseif ( ! isset( $id_token_obj->sub ) && isset( $id_token_obj->user_id ) ) {
			$id_token_obj->sub = $id_token_obj->user_id;
		}
		return $id_token_obj;
	}

	/**
	 * Generate the Auth0 logout URL.
	 *
	 * @param null $return_to - Site URL to return to after logging out.
	 *
	 * @return string
	 *
	 * @codeCoverageIgnore - Private method
	 */
	private function auth0_logout_url( $return_to = null ) {
		if ( ! $return_to ) {
			$return_to = home_url();
		}
		return sprintf(
			'https://%s/v2/logout?client_id=%s&returnTo=%s',
			$this->a0_options->get_auth_domain(),
			$this->a0_options->get( 'client_id' ),
			rawurlencode( $return_to )
		);
	}
}

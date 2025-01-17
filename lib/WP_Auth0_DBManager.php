<?php

class WP_Auth0_DBManager {

	protected $current_db_version = null;
	protected $a0_options;

	public function __construct( WP_Auth0_Options $a0_options ) {
		$this->a0_options = $a0_options;
	}

	/**
	 * @deprecated - 3.10.0, will move add_action calls out of this class in the next major.
	 *
	 * @codeCoverageIgnore - Deprecated.
	 */
	public function init() {
		$this->current_db_version = (int) get_option( 'auth0_db_version', 0 );
		if ( $this->current_db_version === 0 ) {
			$this->current_db_version = (int) get_site_option( 'auth0_db_version', 0 );
		}

		add_action( 'plugins_loaded', [ $this, 'check_update' ] );
	}

	public function check_update() {
		if ( $this->current_db_version && $this->current_db_version !== AUTH0_DB_VERSION ) {
			$this->install_db();
		}
	}

	public function install_db( $version_to_install = null ) {

		wp_cache_set( 'doing_db_update', true, WPA0_CACHE_GROUP );

		$options = $this->a0_options;

		// Plugin version < 3.1.6
		if ( ( $this->current_db_version < 9 && 0 !== $this->current_db_version ) || 9 === $version_to_install ) {
			$this->migrate_users_data();
		}

		// Plugin version < 3.2.22
		if ( $this->current_db_version < 14 && is_null( $options->get( 'client_secret_b64_encoded' ) ) ) {
			if ( $options->get( 'client_id' ) ) {
				$options->set( 'client_secret_b64_encoded', true, false );
			} else {
				$options->set( 'client_secret_b64_encoded', false, false );
			}
		}

		// Plugin version < 3.4.0
		if ( $this->current_db_version < 15 || 15 === $version_to_install ) {
			$options->set( 'cdn_url', WPA0_LOCK_CDN_URL, false );
			$options->set( 'cache_expiration', 1440, false );

			// Update Client
			if ( WP_Auth0::ready() ) {
				$options->set( 'client_signing_algorithm', 'HS256', false );
			}
		}

		// Plugin version < 3.5.0
		if ( ( $this->current_db_version < 16 && 0 !== $this->current_db_version ) || 16 === $version_to_install ) {

			// Update Lock and Auth versions
			if ( '//cdn.auth0.com/js/lock/11.0.0/lock.min.js' === $options->get( 'cdn_url' ) ) {
				$options->set( 'cdn_url', WPA0_LOCK_CDN_URL, false );
			}
		}

		// Plugin version < 3.6.0
		if ( ( $this->current_db_version < 18 && 0 !== $this->current_db_version ) || 18 === $version_to_install ) {

			// Migrate passwordless_method
			if ( $options->get( 'passwordless_enabled', false ) ) {
				$pwl_method = $options->get( 'passwordless_method' );
				switch ( $pwl_method ) {

					// SMS passwordless just needs 'sms' as a connection
					case 'sms':
						$options->set( 'lock_connections', 'sms', false );
						break;

					// Social + SMS means there are existing social connections we want to keep
					case 'socialOrSms':
						$options->add_lock_connection( 'sms' );
						break;

					// Email link passwordless just needs 'email' as a connection
					case 'emailcode':
					case 'magiclink':
						$options->set( 'lock_connections', 'email', false );
						break;

					// Social + Email means there are social connections be want to keep
					case 'socialOrMagiclink':
					case 'socialOrEmailcode':
						$options->add_lock_connection( 'email' );
						break;
				}

				// Need to set a special passwordlessMethod flag if using email code
				$lock_json                               = trim( $options->get( 'extra_conf' ) );
				$lock_json_decoded                       = ! empty( $lock_json ) ? json_decode( $lock_json, true ) : [];
				$lock_json_decoded['passwordlessMethod'] = strpos( $pwl_method, 'code' ) ? 'code' : 'link';
				$options->set( 'extra_conf', json_encode( $lock_json_decoded ), false );
			}

			$options->remove( 'passwordless_method' );
		}

		// 3.9.0
		if ( ( $this->current_db_version < 20 && 0 !== $this->current_db_version ) || 20 === $version_to_install ) {

			// Remove default IP addresses from saved field.
			$migration_ips = trim( $options->get( 'migration_ips' ) );
			if ( $migration_ips ) {
				$migration_ips = array_map( 'trim', explode( ',', $migration_ips ) );
				$ip_check      = new WP_Auth0_Ip_Check( $options );
				$default_ips   = explode( ',', $ip_check->get_ips_by_domain() );
				$custom_ips    = array_diff( $migration_ips, $default_ips );
				$options->set( 'migration_ips', implode( ',', $custom_ips ), false );
			}
		}

		// 3.10.0
		if ( ( $this->current_db_version < 21 && 0 !== $this->current_db_version ) || 21 === $version_to_install ) {

			if ( 'https://cdn.auth0.com/js/lock/11.5/lock.min.js' === $options->get( 'cdn_url' ) ) {
				$options->set( 'cdn_url', WPA0_LOCK_CDN_URL, false );
				$options->set( 'custom_cdn_url', null, false );
			} else {
				$options->set( 'custom_cdn_url', 1, false );
			}

			// Nullify and delete all removed options.
			$options->remove( 'auth0js-cdn' );
			$options->remove( 'passwordless_cdn_url' );
			$options->remove( 'cdn_url_legacy' );

			$options->remove( 'social_twitter_key' );
			$options->remove( 'social_twitter_secret' );
			$options->remove( 'social_facebook_key' );
			$options->remove( 'social_facebook_secret' );
			$options->remove( 'connections' );

			$options->remove( 'chart_idp_type' );
			$options->remove( 'chart_gender_type' );
			$options->remove( 'chart_age_type' );
			$options->remove( 'chart_age_from' );
			$options->remove( 'chart_age_to' );
			$options->remove( 'chart_age_step' );

			// Migrate WLE setting
			$new_wle_value = $options->get( 'wordpress_login_enabled' ) ? 'link' : 'isset';
			$options->set( 'wordpress_login_enabled', $new_wle_value, false );
			$options->set( 'wle_code', str_shuffle( uniqid() . uniqid() ), false );

			// Remove Client Grant update notifications.
			delete_option( 'wp_auth0_client_grant_failed' );
			delete_option( 'wp_auth0_grant_types_failed' );
			delete_option( 'wp_auth0_client_grant_success' );
			delete_option( 'wp_auth0_grant_types_success' );
		}

		// 3.11.0
		if ( ( $this->current_db_version < 22 && 0 !== $this->current_db_version ) || 22 === $version_to_install ) {
			$options->remove( 'social_big_buttons' );
		}

		// 4.0.0
		if ( ( $this->current_db_version < 23 && 0 !== $this->current_db_version ) || 23 === $version_to_install ) {
			$extra_conf = json_decode( $options->get( 'extra_conf' ), true );
			if ( empty( $extra_conf ) ) {
				$extra_conf = [];
			}

			$language = $options->get( 'language' );
			if ( $language ) {
				$extra_conf['language'] = $language;
			}
			$options->remove( 'language' );

			$language_dict = json_decode( $options->get( 'language_dictionary' ), true );
			if ( $language_dict ) {
				$extra_conf['languageDictionary'] = $language_dict;
			}
			$options->remove( 'language_dictionary' );

			if ( ! empty( $extra_conf ) ) {
				$options->set( 'extra_conf', wp_json_encode( $extra_conf ) );
			}

			$options->remove( 'jwt_auth_integration' );
			$options->remove( 'link_auth0_users' );
			$options->remove( 'custom_css' );
			$options->remove( 'custom_js' );
		}

		$options->update_all();

		$this->current_db_version = AUTH0_DB_VERSION;
		update_option( 'auth0_db_version', AUTH0_DB_VERSION );

		wp_cache_set( 'doing_db_update', false, WPA0_CACHE_GROUP );
	}

	/**
	 * Display a banner if we are not able to get a Management API token.
	 *
	 * @deprecated - 3.10.0, not used.
	 *
	 * @codeCoverageIgnore - Deprecated.
	 */
	public function notice_failed_client_grant() {

		if (
			( get_option( 'wp_auth0_client_grant_failed' ) || get_option( 'wp_auth0_grant_types_failed' ) )
			&& current_user_can( 'update_plugins' )
		) {

			if ( WP_Auth0_Api_Client::get_client_token() ) {
				delete_option( 'wp_auth0_client_grant_failed' );
				delete_option( 'wp_auth0_grant_types_failed' );
			} else {
				?>
				<div class="notice notice-error">
					<p><strong><?php _e( 'IMPORTANT!', 'wp-auth0' ); ?></strong></p>
					<p>
					<?php
						printf(
							// translators: Placeholder is the plugin version.
							__( 'WP-Auth0 has upgraded to %s but could not complete the upgrade in your Auth0 dashboard.', 'wp-auth0' ),
							WPA0_VERSION
						);
					?>
						<?php _e( 'This can be fixed one of 2 ways:', 'wp-auth0' ); ?></p>
					<p><strong>1.</strong>
						<a href="https://auth0.com/docs/api/management/v2/tokens#get-a-token-manually" target="_blank">
						<?php
							_e( 'Create a new Management API token', 'wp-auth0' )
						?>
							</a>
						<?php _e( 'and save it in the Auth0 > Settings > Basic tab > API Token field.', 'wp-auth0' ); ?>
						<?php _e( 'This will run the update process again.', 'wp-auth0' ); ?></p>
					<p><strong>2.</strong>
						<a href="https://auth0.com/docs/cms/wordpress/configuration#client-setup"
						   target="_blank">
						   <?php
							_e( 'Review your Application advanced settings', 'wp-auth0' )
							?>
							</a>,
						<?php _e( 'specifically the Grant Types, and ', 'wp-auth0' ); ?>
						<a href="https://auth0.com/docs/cms/wordpress/configuration#authorize-the-application-for-the-management-api"
						   target="_blank">
						   <?php
							_e( 'authorize your client for the Management API', 'wp-auth0' )
							?>
							</a>
						<?php _e( 'to manually complete the setup.', 'wp-auth0' ); ?>
					</p>
					<p><?php _e( 'This banner will disappear once the process is complete.', 'wp-auth0' ); ?></p>
				</div>
				<?php
			}
		}
	}

	/**
	 * Display a banner once after 3.5.0 upgrade.
	 *
	 * @deprecated - 3.10.0, not used.
	 *
	 * @codeCoverageIgnore - Deprecated.
	 */
	public function notice_successful_client_grant() {

		if ( ! get_option( 'wp_auth0_client_grant_success' ) ) {
			return;
		}
		?>
		<div class="notice notice-success">
			<p>
			<?php
				_e( 'As a part of this upgrade, a Client Grant was created for the Auth0 Management API.', 'wp-auth0' );
			?>
				<br>
				<?php
				_e( 'Please check the plugin error log for any additional instructions to complete the upgrade.', 'wp-auth0' );
				?>
			<br><a href="<?php echo admin_url( 'admin.php?page=wpa0-errors' ); ?>">
					<strong><?php _e( 'Error Log', 'wp-auth0' ); ?></strong></a></p>
		</div>
		<?php
		delete_option( 'wp_auth0_client_grant_success' );
	}

	/**
	 * Display a banner once after 3.5.1 upgrade.
	 *
	 * @deprecated - 3.10.0, not used.
	 *
	 * @codeCoverageIgnore - Deprecated.
	 */
	public function notice_successful_grant_types() {

		if ( ! get_option( 'wp_auth0_grant_types_success' ) ) {
			return;
		}
		?>
		<div class="notice notice-success">
			<p>
			<?php
				_e( 'As a part of this upgrade, your Client Grant Types have been updated, if needed.', 'wp-auth0' );
			?>
				</p>
		</div>
		<?php
		delete_option( 'wp_auth0_grant_types_success' );
	}

	protected function migrate_users_data() {
		global $wpdb;

		$wpdb->auth0_user = $wpdb->prefix . 'auth0_user';

		$sql = 'SELECT a.*
				FROM ' . $wpdb->auth0_user . ' a
				JOIN ' . $wpdb->users . ' u ON a.wp_id = u.id;';

		$userRows = $wpdb->get_results( $sql );

		if ( is_null( $userRows ) ) {
			return;
		} elseif ( $userRows instanceof WP_Error ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $userRows );
			return;
		}

		$repo = new WP_Auth0_UsersRepo( $this->a0_options );

		foreach ( $userRows as $row ) {
			$auth0_id = WP_Auth0_UsersRepo::get_meta( $row->wp_id, 'auth0_id' );

			if ( ! $auth0_id ) {
				$repo->update_auth0_object( $row->wp_id, WP_Auth0_Serializer::unserialize( $row->auth0_obj ) );
			}
		}
	}

	public function get_auth0_users( $user_ids = null ) {
		global $wpdb;

		if ( $user_ids === null ) {
			$query = [ 'meta_key' => $wpdb->prefix . 'auth0_id' ];
		} else {
			$query = [
				'meta_query' => [
					'key'     => $wpdb->prefix . 'auth0_id',
					'value'   => $user_ids,
					'compare' => 'IN',
				],
			];
		}
		$query['blog_id'] = 0;

		$results = get_users( $query );

		if ( $results instanceof WP_Error ) {
			WP_Auth0_ErrorManager::insert_auth0_error( __METHOD__, $results->get_error_message() );
			return [];
		}

		return $results;
	}
}

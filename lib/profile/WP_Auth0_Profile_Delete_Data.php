<?php
/**
 * Contains class WP_Auth0_Profile_Delete_Data.
 *
 * @package WP-Auth0
 *
 * @since 3.8.0
 */

/**
 * Class WP_Auth0_Profile_Delete_Data.
 * Provides UI and AJAX handlers to delete a user's Auth0 data.
 */
class WP_Auth0_Profile_Delete_Data {

	/**
	 * WP_Auth0_UsersRepo instance.
	 *
	 * @var WP_Auth0_UsersRepo
	 */
	protected $users_repo;

	/**
	 * WP_Auth0_Profile_Delete_Data constructor.
	 *
	 * @param WP_Auth0_UsersRepo $users_repo - WP_Auth0_UsersRepo instance.
	 */
	public function __construct( WP_Auth0_UsersRepo $users_repo ) {
		$this->users_repo = $users_repo;
	}

	/**
	 * Add actions and filters for the profile page.
	 *
	 * @deprecated - 3.10.0, will move add_action calls out of this class in the next major.
	 *
	 * @codeCoverageIgnore - Deprecated.
	 */
	public function init() {
		add_action( 'edit_user_profile', [ $this, 'show_delete_identity' ] );
		add_action( 'show_user_profile', [ $this, 'show_delete_identity' ] );
		add_action( 'wp_ajax_auth0_delete_data', [ $this, 'delete_user_data' ] );
	}

	/**
	 * Show the delete Auth0 user data button.
	 * Hooked to: edit_user_profile, show_user_profile
	 * IMPORTANT: Internal callback use only, do not call this function directly!
	 */
	public function show_delete_identity() {

		if ( ! isset( $GLOBALS['user_id'] ) || ! current_user_can( 'edit_users', $GLOBALS['user_id'] ) ) {
			return;
		}

		$auth0_user = get_auth0userinfo( $GLOBALS['user_id'] );
		if ( ! $auth0_user ) {
			return;
		}

		?>
		<table class="form-table">
			<tr>
				<th>
					<label><?php _e( 'Delete Auth0 Data', 'wp-auth0' ); ?></label>
				</th>
				<td>
					<input type="button" id="auth0_delete_data" class="button button-secondary"
						value="<?php _e( 'Delete Auth0 Data', 'wp-auth0' ); ?>" />
					<br><br>
					<a href="https://manage.auth0.com/#/users/<?php echo rawurlencode( $auth0_user->sub ); ?>" target="_blank">
						<?php _e( 'View in Auth0', 'wp-auth0' ); ?>
					</a>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * AJAX function to delete Auth0 data in the usermeta table.
	 * Hooked to: wp_ajax_auth0_delete_data
	 * IMPORTANT: Internal callback use only, do not call this function directly!
	 */
	public function delete_user_data() {
		check_ajax_referer( 'delete_auth0_identity' );

		if ( empty( $_POST['user_id'] ) ) {
			wp_send_json_error( [ 'error' => __( 'Empty user_id', 'wp-auth0' ) ] );
		}

		$user_id = $_POST['user_id'];

		if ( ! current_user_can( 'edit_users' ) ) {
			wp_send_json_error( [ 'error' => __( 'Forbidden', 'wp-auth0' ) ] );
		}

		$this->users_repo->delete_auth0_object( $user_id );
		wp_send_json_success();
	}
}

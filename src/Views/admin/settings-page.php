<?php

declare(strict_types=1);

/**
 * Admin settings page view.
 *
 * @package OWC_Activity_Log
 * @author  Yard | Digital Agency
 * @since   1.0.0
 */

/**
 * Exit when accessed directly.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$settings   = owc_activity_log_get_settings();
$all_groups = owc_activity_log_all_groups();
// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

?>
<div class="wrap">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

	<?php settings_errors( 'owc_at_settings' ); ?>

	<form method="post">
		<?php wp_nonce_field( 'owc_at_save_settings', 'owc_at_settings_nonce' ); ?>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">
					<label for="retention_days"><?php esc_html_e( 'Log retention (days)', 'owc-activity-log' ); ?></label>
				</th>
				<td>
					<input
						type="number"
						id="retention_days"
						name="retention_days"
						value="<?php echo esc_attr( $settings['retention_days'] ); ?>"
						min="1"
						max="3650"
						class="small-text"
					>
					<p class="description"><?php esc_html_e( 'Log entries older than this number of days are deleted automatically.', 'owc-activity-log' ); ?></p>
				</td>
			</tr>

			<tr>
				<th scope="row">
					<label for="log_ip"><?php esc_html_e( 'Log IP addresses', 'owc-activity-log' ); ?></label>
				</th>
				<td>
					<label>
						<input
							type="checkbox"
							id="log_ip"
							name="log_ip"
							value="1"
							<?php checked( $settings['log_ip'] ); ?>
						>
						<?php esc_html_e( 'Enable IP address logging', 'owc-activity-log' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'When enabled, the IP address of the user is stored with each log entry.', 'owc-activity-log' ); ?></p>
				</td>
			</tr>

			<tr>
				<th scope="row">
					<?php esc_html_e( 'Tracked groups', 'owc-activity-log' ); ?>
				</th>
				<td>
					<?php foreach ( $all_groups as $group ) : // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound ?>
						<label style="display:block;margin-bottom:4px;">
							<input
								type="checkbox"
								name="enabled_groups[]"
								value="<?php echo esc_attr( $group ); ?>"
								<?php checked( in_array( $group, $settings['enabled_groups'], true ) ); ?>
							>
							<?php echo esc_html( $group ); ?>
						</label>
					<?php endforeach; ?>
					<p class="description"><?php esc_html_e( 'Uncheck groups to stop tracking them.', 'owc-activity-log' ); ?></p>
				</td>
			</tr>

			<tr>
				<th scope="row">
					<label for="ignored_meta_keys"><?php esc_html_e( 'Ignored meta keys', 'owc-activity-log' ); ?></label>
				</th>
				<td>
					<textarea
						id="ignored_meta_keys"
						name="ignored_meta_keys"
						rows="6"
						class="large-text code"
					><?php echo esc_textarea( implode( "\n", $settings['ignored_meta_keys'] ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One key per line. Wildcards supported: _my_prefix_*', 'owc-activity-log' ); ?></p>
				</td>
			</tr>

			<tr>
				<th scope="row">
					<label for="ignored_option_names"><?php esc_html_e( 'Ignored option names', 'owc-activity-log' ); ?></label>
				</th>
				<td>
					<textarea
						id="ignored_option_names"
						name="ignored_option_names"
						rows="6"
						class="large-text code"
					><?php echo esc_textarea( implode( "\n", $settings['ignored_option_names'] ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One option name per line. Wildcards supported: my_plugin_*', 'owc-activity-log' ); ?></p>
				</td>
			</tr>

			<tr>
				<th scope="row">
					<label for="ignored_post_types"><?php esc_html_e( 'Ignored post types', 'owc-activity-log' ); ?></label>
				</th>
				<td>
					<textarea
						id="ignored_post_types"
						name="ignored_post_types"
						rows="6"
						class="large-text code"
					><?php echo esc_textarea( implode( "\n", $settings['ignored_post_types'] ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One post type per line. Posts of these types are not logged. Wildcards supported: my_cpt_*', 'owc-activity-log' ); ?></p>
				</td>
			</tr>
		</table>

		<h2><?php esc_html_e( 'SIEM integration', 'owc-activity-log' ); ?></h2>
		<p><?php esc_html_e( 'Forward every logged event as JSON via a POST request to an external SIEM. Leave the endpoint empty to disable.', 'owc-activity-log' ); ?></p>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">
					<label for="siem_endpoint"><?php esc_html_e( 'SIEM endpoint URL', 'owc-activity-log' ); ?></label>
				</th>
				<td>
					<input
						type="url"
						id="siem_endpoint"
						name="siem_endpoint"
						value="<?php echo esc_attr( $settings['siem_endpoint'] ); ?>"
						placeholder="https://"
						pattern="https://.+"
						class="regular-text code"
					>
					<p class="description"><?php esc_html_e( 'Only HTTPS URLs are accepted.', 'owc-activity-log' ); ?></p>
				</td>
			</tr>

			<tr>
				<th scope="row">
					<label for="siem_token"><?php esc_html_e( 'SIEM API token', 'owc-activity-log' ); ?></label>
				</th>
				<td>
					<input
						type="password"
						id="siem_token"
						name="siem_token"
						value=""
						autocomplete="new-password"
						placeholder="<?php echo '' !== $settings['siem_token'] ? esc_attr__( 'Token saved', 'owc-activity-log' ) : ''; ?>"
						class="regular-text code"
					>
					<?php if ( '' !== $settings['siem_token'] ) : ?>
						<label style="display:block;margin-top:4px;">
							<input type="checkbox" name="siem_token_clear" value="1">
							<?php esc_html_e( 'Remove saved token', 'owc-activity-log' ); ?>
						</label>
					<?php endif; ?>
					<p class="description"><?php esc_html_e( 'Optional. Sent as "Authorization: Bearer <token>" header. Leave empty to keep the saved token.', 'owc-activity-log' ); ?></p>
				</td>
			</tr>
		</table>

		<table class="form-table" role="presentation">
			<?php do_settings_fields( 'owc-activity-log-settings', 'owc_activity_log_inventory' ); ?>
		</table>

		<?php submit_button(); ?>
	</form>
</div>

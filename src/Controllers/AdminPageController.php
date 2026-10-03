<?php

declare(strict_types=1);

/**
 * Admin page controller.
 *
 * @package OWC_Activity_Log
 * @author  Yard | Digital Agency
 * @since   1.0.0
 */

namespace OWCActivityLog\Controllers;

/**
 * Exit when accessed directly.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use OWCActivityLog\Admin\ActivityLogTable;
use OWCActivityLog\Database\ActivityRepository;

/**
 * Renders admin pages for the activity tracker.
 *
 * @since 1.0.0
 */
class AdminPageController {

	/**
	 * Render the activity log page.
	 */
	public function render_log(): void {
		if ( ! current_user_can( settings_page_cap() ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'owc-activity-log' ) );
		}

		$table        = new ActivityLogTable();
		$repository   = new ActivityRepository();
		$groups       = $repository->get_groups();
		$object_types = $repository->get_object_types();

		$table->prepare_items();

		owc_activity_log_render_view(
			'admin/log-page',
			array(
				'table'        => $table,
				'groups'       => $groups,
				'object_types' => $object_types,
			)
		);
	}

	/**
	 * Render the settings page.
	 */
	public function render_settings(): void {
		if ( ! current_user_can( settings_page_cap() ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'owc-activity-log' ) );
		}

		if ( isset( $_POST['owc_at_settings_nonce'] ) &&
			wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['owc_at_settings_nonce'] ) ), 'owc_at_save_settings' )
		) {
			$this->save_settings();
		}

		owc_activity_log_render_view( 'admin/settings-page' );
	}

	/**
	 * Save settings from POST data.
	 */
	private function save_settings(): void {
		$all_groups = owc_activity_log_all_groups();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- already verified above
		$retention_days = isset( $_POST['retention_days'] ) ? absint( $_POST['retention_days'] ) : OWC_ACTIVITY_LOG_DEFAULT_RETENTION_DAYS;
		$retention_days = max( 1, min( 3650, $retention_days ) );

		$raw_meta_keys = isset( $_POST['ignored_meta_keys'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ignored_meta_keys'] ) ) : '';
		$ignored_meta  = array_filter( array_map( 'trim', explode( "\n", $raw_meta_keys ) ) );

		$raw_options     = isset( $_POST['ignored_option_names'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ignored_option_names'] ) ) : '';
		$ignored_options = array_filter( array_map( 'trim', explode( "\n", $raw_options ) ) );

		$raw_post_types     = isset( $_POST['ignored_post_types'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ignored_post_types'] ) ) : '';
		$ignored_post_types = array_filter( array_map( 'trim', explode( "\n", $raw_post_types ) ) );

		$posted_groups  = isset( $_POST['enabled_groups'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['enabled_groups'] ) ) : array();
		$enabled_groups = array_intersect( $posted_groups, $all_groups );

		$log_ip         = isset( $_POST['log_ip'] ) && '1' === $_POST['log_ip'];
		$inventory_push = isset( $_POST['wazuh_siem_enable_inventory_push'] ) && '1' === $_POST['wazuh_siem_enable_inventory_push'];

		$current       = owc_activity_log_get_settings();
		$raw_endpoint  = isset( $_POST['siem_endpoint'] ) ? trim( (string) wp_unslash( $_POST['siem_endpoint'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized below
		$siem_endpoint = esc_url_raw( $raw_endpoint, array( 'https' ) );

		if ( '' !== $raw_endpoint && ( '' === $siem_endpoint || ! wp_parse_url( $siem_endpoint, PHP_URL_HOST ) ) ) {
			$siem_endpoint = $current['siem_endpoint'];

			add_settings_error(
				'owc_at_settings',
				'invalid_siem_endpoint',
				__( 'The SIEM endpoint must be a valid HTTPS URL. The previous value has been kept.', 'owc-activity-log' )
			);
		}

		// An empty token field keeps the stored token, so it never has to be rendered in the form.
		$siem_token = (string) $current['siem_token'];

		if ( ! empty( $_POST['siem_token_clear'] ) ) {
			$siem_token = '';
		} elseif ( ! empty( $_POST['siem_token'] ) ) {
			// Printable ASCII only; also prevents header injection.
			$siem_token = (string) preg_replace( '/[^\x21-\x7E]/', '', (string) wp_unslash( $_POST['siem_token'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}
		// phpcs:enable

		update_option(
			OWC_ACTIVITY_LOG_SETTINGS_KEY,
			array(
				'retention_days'       => $retention_days,
				'log_ip'               => $log_ip,
				'ignored_meta_keys'    => array_values( $ignored_meta ),
				'ignored_option_names' => array_values( $ignored_options ),
				'ignored_post_types'   => array_values( $ignored_post_types ),
				'enabled_groups'       => array_values( $enabled_groups ),
				'siem_endpoint'        => $siem_endpoint,
				'siem_token'           => $siem_token,
			)
		);
		update_option( 'wazuh_siem_enable_inventory_push', $inventory_push );

		add_settings_error(
			'owc_at_settings',
			'saved',
			__( 'Settings saved.', 'owc-activity-log' ),
			'updated'
		);
	}
}

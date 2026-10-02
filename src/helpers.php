<?php

declare(strict_types=1);

/**
 * Plugin helper functions.
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

/**
 * Render a view template.
 *
 * @since 1.0.0
 */
function owc_activity_log_render_view( string $view, array $data = array() ): void
{
	$file = OWC_ACTIVITY_LOG_DIR_PATH . 'src/Views/' . $view . '.php';

	if ( ! file_exists( $file ) ) {
		return;
	}

	// Extract data into local scope.
	extract( $data ); // phpcs:ignore WordPress.PHP.DontExtract.extract_extract

	include $file;
}

/**
 * The full set of selectable activity groups, used as the settings page
 * checkbox list, the enabled-by-default list, and the save-time whitelist.
 *
 * @since 1.1.0
 */
function owc_activity_log_all_groups(): array
{
	return array(
		'posts',
		'meta',
		'users',
		'options',
		'taxonomy',
		'comments',
		'media',
		'plugins',
		'themes',
		'menus',
		'widgets',
		'gravity_forms',
	);
}

/**
 * Get plugin settings.
 *
 * @since 1.0.0
 */
function owc_activity_log_get_settings(): array
{
	$defaults = array(
		'retention_days'       => OWC_ACTIVITY_LOG_DEFAULT_RETENTION_DAYS,
		'log_ip'               => false,
		'ignored_meta_keys'    => array(),
		'ignored_option_names' => array(),
		'ignored_post_types'   => array(),
		'enabled_groups'       => owc_activity_log_all_groups(),
		'siem_endpoint'        => '',
		'siem_token'           => '',
	);

	$saved = get_option( OWC_ACTIVITY_LOG_SETTINGS_KEY, array() );
	$saved = wp_parse_args( $saved, $defaults );

	return is_array( $saved ) ? $saved : $defaults;
}

/**
 * One-time migration for sites that saved settings before 'gravity_forms'
 * existed as a selectable group: since that checkbox didn't exist yet, no
 * admin could have explicitly disabled it, so it's safe to add it to their
 * already-saved enabled_groups. Without this, wp_parse_args() in
 * owc_activity_log_get_settings() lets the saved (gravity_forms-less)
 * enabled_groups list win outright, and the new GF listener stays silently
 * disabled until someone re-saves the settings page.
 *
 * @since 1.1.0
 */
function owc_activity_log_maybe_migrate_enabled_groups(): void
{
	if ( get_option( 'owc_activity_log_gf_group_migrated' ) ) {
		return;
	}

	$saved = get_option( OWC_ACTIVITY_LOG_SETTINGS_KEY );

	if ( is_array( $saved )
		&& isset( $saved['enabled_groups'] )
		&& is_array( $saved['enabled_groups'] )
		&& ! in_array( 'gravity_forms', $saved['enabled_groups'], true )
	) {
		$saved['enabled_groups'][] = 'gravity_forms';

		update_option( OWC_ACTIVITY_LOG_SETTINGS_KEY, $saved );
	}

	update_option( 'owc_activity_log_gf_group_migrated', true );
}

/**
 * Check whether a given group is enabled in settings.
 *
 * @since 1.0.0
 */
function owc_activity_log_group_enabled( string $group ): bool
{
	$settings = owc_activity_log_get_settings();

	return in_array( $group, $settings['enabled_groups'], true );
}

/**
 * @since 1.0.2
 */
function settings_page_cap(): string
{
	$cap = apply_filters( 'owc_activity_log_admin_page_overview_cap', OWC_ACTIVITY_LOG_SETTINGS_PAGE_CAP );

	return is_string( $cap ) && '' !== trim( $cap ) ? $cap : OWC_ACTIVITY_LOG_SETTINGS_PAGE_CAP;
}

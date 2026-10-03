<?php

declare(strict_types=1);

/**
 * SIEM service provider.
 *
 * @package OWC_Activity_Log
 * @author  Yard | Digital Agency
 * @since   1.3.0
 */

namespace OWCActivityLog\Providers;

/**
 * Exit when accessed directly.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use OWCActivityLog\Siem\SiemDispatcher;

/**
 * Forwards activity entries to a SIEM endpoint when one is configured.
 *
 * @since 1.3.0
 */
class SiemServiceProvider extends ServiceProvider {
	private const INVENTORY_OPTION = 'wazuh_siem_enable_inventory_push';
	private const INVENTORY_CRON   = 'wazuh_siem_daily_inventory_push';
	private const INVENTORY_HASH   = 'wazuh_siem_last_inventory_hash';

	public function register(): void {
		add_action( 'admin_init', $this->register_inventory_settings( ... ) );
		add_action( 'update_option_' . self::INVENTORY_OPTION, $this->handle_inventory_toggle_change( ... ), 10, 2 );
		add_action( 'add_option_' . self::INVENTORY_OPTION, $this->handle_inventory_option_added( ... ), 10, 2 );
		add_action( self::INVENTORY_CRON, $this->push_daily_inventory_to_siem( ... ) );
		add_action( 'activated_plugin', $this->push_inventory_to_siem( ... ) );
		add_action( 'deactivated_plugin', $this->push_inventory_to_siem( ... ) );
		add_action( 'deleted_plugin', $this->push_inventory_to_siem( ... ) );
		add_action( 'upgrader_process_complete', $this->check_upgrader_plugin_push( ... ), 10, 2 );

		$settings = owc_activity_log_get_settings();
		$endpoint = (string) ( $settings['siem_endpoint'] ?? '' );

		if ( '' === $endpoint ) {
			$this->log_inventory_debug( 'Inventory push skipped: no SIEM endpoint is configured.' );
			return;
		}

		$dispatcher = new SiemDispatcher( $endpoint, (string) ( $settings['siem_token'] ?? '' ) );

		add_action( 'owc_activity_log_entry_logged', $dispatcher->queue( ... ) );
		add_action( 'shutdown', $dispatcher->flush( ... ), PHP_INT_MAX );
	}

	/** Register the inventory setting and its checkbox field. */
	public function register_inventory_settings(): void {
		register_setting(
			'owc_activity_log_settings',
			self::INVENTORY_OPTION,
			array(
				'type'              => 'boolean',
				'default'           => false,
				'sanitize_callback' => static fn( $value ) => (bool) $value,
			)
		);

		add_settings_section( 'owc_activity_log_inventory', '', '__return_false', 'owc-activity-log-settings' );
		add_settings_field(
			self::INVENTORY_OPTION,
			__( 'Enable Plugin Inventory Push', 'owc-activity-log' ),
			$this->render_inventory_checkbox( ... ),
			'owc-activity-log-settings',
			'owc_activity_log_inventory'
		);
	}

	/** Render the registered inventory setting checkbox. */
	public function render_inventory_checkbox(): void {
		printf(
			'<label for="%1$s"><input type="checkbox" id="%1$s" name="%1$s" value="1" %2$s> %3$s</label>',
			esc_attr( self::INVENTORY_OPTION ),
			checked( get_option( self::INVENTORY_OPTION, false ), true, false ),
			esc_html__( 'Periodically send installed plugin versions to Wazuh for automated CVE & vulnerability scanning.', 'owc-activity-log' )
		);
	}

	/** Handle changes to an existing inventory setting. */
	public function handle_inventory_toggle_change( mixed $old_value, mixed $new_value ): void {
		$this->apply_inventory_setting( $new_value );
	}

	/** Handle the first save, where WordPress adds rather than updates the option. */
	public function handle_inventory_option_added( string $option, mixed $value ): void {
		$this->apply_inventory_setting( $value );
	}

	private function apply_inventory_setting( mixed $enabled ): void {
		if ( $enabled ) {
			if ( ! wp_next_scheduled( self::INVENTORY_CRON ) ) {
				wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', self::INVENTORY_CRON );
			}

			$this->send_inventory( true );
			return;
		}

		wp_clear_scheduled_hook( self::INVENTORY_CRON );
	}

	/** Collect every installed plugin and its active state. */
	public function collect_plugin_inventory(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins                = get_plugins();
		$active_plugins         = (array) get_option( 'active_plugins', array() );
		$network_active_plugins = (array) get_site_option( 'active_sitewide_plugins', array() );
		$inventory              = array();

		foreach ( $plugins as $plugin_file => $plugin_data ) {
			$directory = dirname( $plugin_file );
			$slug      = '.' === $directory ? basename( $plugin_file, '.php' ) : strtok( $plugin_file, '/' );

			$inventory[] = array(
				'slug'    => $slug,
				'name'    => (string) ( $plugin_data['Name'] ?? $plugin_file ),
				'version' => (string) ( $plugin_data['Version'] ?? '' ),
				'status'  => in_array( $plugin_file, $active_plugins, true ) || isset( $network_active_plugins[ $plugin_file ] ) ? 'active' : 'inactive',
			);
		}

		return $inventory;
	}

	/** Send inventory on the daily cron, bypassing event deduplication. */
	public function push_daily_inventory_to_siem(): void {
		if ( ! get_option( self::INVENTORY_OPTION, false ) ) {
			return;
		}

		$this->send_inventory( true );
	}

	/** Send inventory after plugin lifecycle events, only when it changed. */
	public function push_inventory_to_siem( mixed ...$args ): void {
		if ( ! get_option( self::INVENTORY_OPTION, false ) ) {
			return;
		}

		$this->send_inventory( false );
	}

	/** Ensure upgrader activity relates to plugins before sending inventory. */
	public function check_upgrader_plugin_push( mixed $upgrader, array $hook_extra ): void {
		if ( ! get_option( self::INVENTORY_OPTION, false ) ) {
			return;
		}

		if ( 'plugin' === ( $hook_extra['type'] ?? '' ) ) {
			$this->send_inventory( false );
		}
	}

	private function send_inventory( bool $force ): void {
		if ( ! get_option( self::INVENTORY_OPTION, false ) ) {
			return;
		}

		$settings = owc_activity_log_get_settings();
		$endpoint = (string) ( $settings['siem_endpoint'] ?? '' );

		if ( '' === $endpoint ) {
			return;
		}

		$plugins = $this->collect_plugin_inventory();
		$payload = array(
			'site'                 => untrailingslashit( (string) preg_replace( '#^https?://#i', '', home_url() ) ),
			'event'                => 'plugin_inventory',
			'timestamp'            => gmdate( 'c' ),
			'total_plugins'        => count( $plugins ),
			'active_plugins_count' => count( array_filter( $plugins, static fn( $plugin ) => 'active' === $plugin['status'] ) ),
			'plugins'              => $plugins,
		);
		$hash    = md5( (string) wp_json_encode( array_diff_key( $payload, array( 'timestamp' => true ) ) ) );

		if ( ! $force && get_option( self::INVENTORY_HASH, '' ) === $hash ) {
			$this->log_inventory_debug( 'Inventory push skipped: inventory has not changed.' );
			return;
		}

		$dispatcher = new SiemDispatcher( $endpoint, (string) ( $settings['siem_token'] ?? '' ) );
		$payload_json = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );

		if ( false !== $payload_json ) {
			$this->log_inventory_debug( 'Inventory payload: ' . $payload_json );
		}

		if ( $dispatcher->send_payload( $payload ) ) {
			update_option( self::INVENTORY_HASH, $hash );
			$this->log_inventory_debug( 'Non-blocking inventory request handed to WordPress HTTP API; remote delivery is not confirmed.' );
			return;
		}

		$this->log_inventory_debug( 'Inventory request could not be handed to WordPress HTTP API.' );
	}

	private function log_inventory_debug( string $message ): void {
		if ( ! defined( 'WP_DEBUG' ) || ! WP_DEBUG || ! defined( 'WP_DEBUG_LOG' ) || ! WP_DEBUG_LOG ) {
			return;
		}

		error_log( '[OWC Activity Log SIEM] ' . $message );
	}
}

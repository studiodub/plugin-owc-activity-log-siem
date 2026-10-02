<?php

declare(strict_types=1);

/**
 * Bootstrap providers.
 *
 * @package OWC_Activity_Log
 * @author  Yard | Digital Agency
 * @since   1.0.0
 */

namespace OWCActivityLog;

/**
 * Exit when accessed directly.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use OWCActivityLog\Providers\AdminServiceProvider;
use OWCActivityLog\Providers\DatabaseServiceProvider;
use OWCActivityLog\Providers\ListenerServiceProvider;
use OWCActivityLog\Providers\MaintenanceServiceProvider;
use OWCActivityLog\Providers\SiemServiceProvider;

require_once __DIR__ . '/helpers.php';

/**
 * Builds and boots all service providers.
 *
 * @since 1.0.0
 */
final class Bootstrap {

	private array $providers;

	public function __construct() {
		owc_activity_log_maybe_migrate_enabled_groups();

		$this->register_plugin_text_domain();
		$this->providers = $this->get_providers();
		$this->register_providers();
		$this->boot_providers();
	}

	/**
	 * @since 1.1.0
	 */
	protected function register_plugin_text_domain(): void {
		add_action(
			'init',
			function () {
				load_plugin_textdomain( 'owc-activity-log', false, dirname( plugin_basename( OWC_ACTIVITY_LOG_FILE ) ) . '/languages' );
			}
		);
	}

	protected function get_providers(): array {
		return array(
			new DatabaseServiceProvider(),
			new ListenerServiceProvider(),
			new AdminServiceProvider(),
			new MaintenanceServiceProvider(),
			new SiemServiceProvider(),
		);
	}

	protected function register_providers(): void {
		foreach ( $this->providers as $provider ) {
			$provider->register();
		}
	}

	protected function boot_providers(): void {
		foreach ( $this->providers as $provider ) {
			$provider->boot();
		}
	}
}

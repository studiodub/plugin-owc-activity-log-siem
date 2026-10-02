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

	public function register(): void {
		$settings = owc_activity_log_get_settings();
		$endpoint = (string) ( $settings['siem_endpoint'] ?? '' );

		if ( '' === $endpoint ) {
			return;
		}

		$dispatcher = new SiemDispatcher( $endpoint, (string) ( $settings['siem_token'] ?? '' ) );

		add_action( 'owc_activity_log_entry_logged', $dispatcher->queue( ... ) );
		add_action( 'shutdown', $dispatcher->flush( ... ), PHP_INT_MAX );
	}
}

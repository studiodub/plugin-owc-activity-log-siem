<?php

declare(strict_types=1);

/**
 * SIEM dispatcher.
 *
 * @package OWC_Activity_Log
 * @author  Yard | Digital Agency
 * @since   1.3.0
 */

namespace OWCActivityLog\Siem;

/**
 * Exit when accessed directly.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Forwards logged activity entries as JSON to an external SIEM endpoint.
 *
 * Entries are queued during the request and sent on shutdown, so logging
 * never blocks or breaks the action that triggered it.
 *
 * @since 1.3.0
 */
class SiemDispatcher {

	private array $queue = array();

	public function __construct(
		private string $endpoint,
		private string $token = ''
	) {
	}

	/**
	 * Queue a logged entry for delivery.
	 */
	public function queue( array $entry ): void {
		$payload = $this->build_payload( $entry );

		if ( ! empty( $payload ) ) {
			$this->queue[] = $payload;
		}
	}

	/**
	 * Send all queued payloads.
	 */
	public function flush(): void {
		if ( empty( $this->queue ) ) {
			return;
		}

		$queue       = $this->queue;
		$this->queue = array();

		// Release the visitor before doing network I/O (PHP-FPM only).
		if ( function_exists( 'fastcgi_finish_request' ) ) {
			fastcgi_finish_request();
		}

		foreach ( $queue as $payload ) {
			// Stop on transport errors so an unreachable endpoint doesn't add a timeout per event.
			if ( ! $this->send( $payload ) ) {
				break;
			}
		}
	}

	/**
	 * Build the JSON payload for a logged entry.
	 */
	public function build_payload( array $entry ): array {
		$group   = (string) ( $entry['group'] ?? '' );
		$action  = (string) ( $entry['action'] ?? '' );
		$created = strtotime( ( $entry['created_at'] ?? '' ) . ' UTC' );
		$meta    = is_string( $entry['meta'] ?? null ) ? json_decode( $entry['meta'], true ) : null;

		$payload = array(
			'site'        => untrailingslashit( (string) preg_replace( '#^https?://#i', '', home_url() ) ),
			'event'       => $group . '_' . $action,
			'user'        => (string) ( $entry['user_login'] ?? '' ),
			'user_id'     => (int) ( $entry['user_id'] ?? 0 ),
			'group'       => $group,
			'action'      => $action,
			'message'     => (string) ( $entry['message'] ?? '' ),
			'object_type' => (string) ( $entry['object_type'] ?? '' ),
			'object_id'   => (int) ( $entry['object_id'] ?? 0 ),
			'timestamp'   => gmdate( 'c', $created ? $created : time() ),
		);

		if ( ! empty( $entry['ip'] ) ) {
			$payload['ip'] = (string) $entry['ip'];
		}

		if ( is_array( $meta ) && ! empty( $meta ) ) {
			$payload['meta'] = $meta;
		}

		/**
		 * Filter the payload sent to the SIEM endpoint. Return an empty array to skip the event.
		 *
		 * @since 1.3.0
		 *
		 * @param array $payload The JSON payload.
		 * @param array $entry   The logged entry.
		 */
		$payload = apply_filters( 'owc_activity_log_siem_payload', $payload, $entry );

		return is_array( $payload ) ? $payload : array();
	}

	/**
	 * POST a single payload. Returns false when the endpoint could not be reached.
	 */
	private function send( array $payload ): bool {
		$body = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );

		if ( false === $body ) {
			return true;
		}

		$headers = array(
			'Content-Type' => 'application/json; charset=utf-8',
			'User-Agent'   => 'OWC-Activity-Log/' . OWC_ACTIVITY_LOG_VERSION,
		);

		if ( '' !== $this->token ) {
			$headers['Authorization'] = 'Bearer ' . $this->token;
		}

		/**
		 * Filter the HTTP request arguments for the SIEM endpoint.
		 *
		 * @since 1.3.0
		 *
		 * @param array $args    Arguments passed to wp_safe_remote_post().
		 * @param array $payload The JSON payload.
		 */
		$args = apply_filters(
			'owc_activity_log_siem_request_args',
			array(
				'timeout'     => 3,
				'redirection' => 0,
				'headers'     => $headers,
				'body'        => $body,
				'data_format' => 'body',
			),
			$payload
		);

		// wp_safe_remote_post() rejects internal hosts to prevent SSRF.
		$response = wp_safe_remote_post( $this->endpoint, $args );
		$code     = (int) wp_remote_retrieve_response_code( $response );

		if ( ! is_wp_error( $response ) && $code >= 200 && $code < 300 ) {
			return true;
		}

		/**
		 * Fires when an event could not be delivered to the SIEM endpoint.
		 *
		 * @since 1.3.0
		 *
		 * @param array|\WP_Error $response The HTTP response or error.
		 * @param array           $payload  The JSON payload.
		 */
		do_action( 'owc_activity_log_siem_request_failed', $response, $payload );

		return ! is_wp_error( $response );
	}
}

<?php

declare(strict_types=1);

/**
 * SiemDispatcher unit tests.
 *
 * @package OWC_Activity_Log
 * @author  Yard | Digital Agency
 * @since   1.3.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use OWCActivityLog\Siem\SiemDispatcher;
use OWCActivityLog\Providers\SiemServiceProvider;

function owc_activity_log_siem_entry( array $overrides = array() ): array {
	return array_merge(
		array(
			'created_at'  => '2026-01-01 12:00:00',
			'group'       => 'themes',
			'action'      => 'file_edited',
			'message'     => 'Theme file edited.',
			'user_id'     => 7,
			'user_login'  => 'suspect_user',
			'object_id'   => 0,
			'object_type' => 'theme',
			'meta'        => '{"file":"functions.php"}',
			'ip'          => '',
		),
		$overrides
	);
}

function owc_activity_log_siem_mock_wp(): void {
	WP_Mock::userFunction( 'home_url' )->andReturn( 'https://met-matthijs.nl' );
	WP_Mock::userFunction( 'untrailingslashit' )->andReturnUsing( fn( $v ) => rtrim( $v, '/\\' ) );
	WP_Mock::userFunction( 'apply_filters' )->andReturnArg( 1 );
	WP_Mock::userFunction( 'wp_json_encode' )->andReturnUsing( fn( $v, $f = 0 ) => json_encode( $v, $f ) );
}

it(
	'builds a payload with site, event, user and decoded meta',
	function () {
		owc_activity_log_siem_mock_wp();

		$payload = ( new SiemDispatcher( 'https://siem.example.com' ) )->build_payload( owc_activity_log_siem_entry() );

		expect( $payload['site'] )->toBe( 'met-matthijs.nl' );
		expect( $payload['event'] )->toBe( 'themes_file_edited' );
		expect( $payload['user'] )->toBe( 'suspect_user' );
		expect( $payload['meta'] )->toBe( array( 'file' => 'functions.php' ) );
		expect( $payload['timestamp'] )->toBe( '2026-01-01T12:00:00+00:00' );
		expect( $payload )->not->toHaveKey( 'ip' );
	}
);

it(
	'includes the IP address only when it was logged',
	function () {
		owc_activity_log_siem_mock_wp();

		$payload = ( new SiemDispatcher( 'https://siem.example.com' ) )->build_payload( owc_activity_log_siem_entry( array( 'ip' => '203.0.113.5' ) ) );

		expect( $payload['ip'] )->toBe( '203.0.113.5' );
	}
);

it(
	'posts queued events as JSON with a bearer token on flush',
	function () {
		owc_activity_log_siem_mock_wp();
		WP_Mock::userFunction( 'is_wp_error' )->andReturn( false );
		WP_Mock::userFunction( 'wp_remote_retrieve_response_code' )->andReturn( 202 );
		WP_Mock::userFunction( 'wp_safe_remote_post' )
			->once()
			->with(
				'https://siem.example.com/ingest',
				Mockery::on(
					function ( $args ) {
						$body = json_decode( $args['body'], true );

						return 'Bearer s3cret' === $args['headers']['Authorization']
							&& 'application/json; charset=utf-8' === $args['headers']['Content-Type']
							&& 0 === $args['redirection']
							&& 'met-matthijs.nl' === $body['site']
							&& 'themes_file_edited' === $body['event'];
					}
				)
			)
			->andReturn( array() );

		$dispatcher = new SiemDispatcher( 'https://siem.example.com/ingest', 's3cret' );
		$dispatcher->queue( owc_activity_log_siem_entry() );
		$dispatcher->flush();
		$dispatcher->flush();
	}
);

it(
	'sends direct payloads without blocking and with a five second timeout',
	function () {
		owc_activity_log_siem_mock_wp();
		WP_Mock::userFunction( 'is_wp_error' )->andReturn( false );
		WP_Mock::userFunction( 'wp_safe_remote_post' )
			->once()
			->with(
				'https://siem.example.com',
				Mockery::on(
					fn( $args ) => false === $args['blocking']
						&& 5 === $args['timeout']
						&& 'plugin_inventory' === json_decode( $args['body'], true )['event']
				)
			)
			->andReturn( array() );

		expect( ( new SiemDispatcher( 'https://siem.example.com' ) )->send_payload( array( 'event' => 'plugin_inventory' ) ) )->toBeTrue();
	}
);

it(
	'does not push inventory when the feature is disabled',
	function () {
		WP_Mock::userFunction( 'get_option' )
			->once()
			->with( 'wazuh_siem_enable_inventory_push', false )
			->andReturn( false );
		WP_Mock::userFunction( 'wp_safe_remote_post' )->never();

		( new SiemServiceProvider() )->push_inventory_to_siem();
	}
);

it(
	'omits the authorization header when no token is set',
	function () {
		owc_activity_log_siem_mock_wp();
		WP_Mock::userFunction( 'is_wp_error' )->andReturn( false );
		WP_Mock::userFunction( 'wp_remote_retrieve_response_code' )->andReturn( 200 );
		WP_Mock::userFunction( 'wp_safe_remote_post' )
			->once()
			->with( Mockery::any(), Mockery::on( fn( $args ) => ! isset( $args['headers']['Authorization'] ) ) )
			->andReturn( array() );

		$dispatcher = new SiemDispatcher( 'https://siem.example.com' );
		$dispatcher->queue( owc_activity_log_siem_entry() );
		$dispatcher->flush();
	}
);

it(
	'skips events when the payload filter returns an empty array',
	function () {
		owc_activity_log_siem_mock_wp();
		WP_Mock::userFunction( 'wp_safe_remote_post' )->never();

		$entry      = owc_activity_log_siem_entry();
		$dispatcher = new SiemDispatcher( 'https://siem.example.com' );
		$payload    = $dispatcher->build_payload( $entry );

		WP_Mock::onFilter( 'owc_activity_log_siem_payload' )->with( $payload, $entry )->reply( array() );

		$dispatcher->queue( $entry );
		$dispatcher->flush();
	}
);

it(
	'stops sending after a transport error',
	function () {
		owc_activity_log_siem_mock_wp();
		WP_Mock::userFunction( 'is_wp_error' )->andReturn( true );
		WP_Mock::userFunction( 'wp_remote_retrieve_response_code' )->andReturn( '' );
		WP_Mock::userFunction( 'wp_safe_remote_post' )->once()->andReturn( new stdClass() );

		$dispatcher = new SiemDispatcher( 'https://siem.example.com' );
		$dispatcher->queue( owc_activity_log_siem_entry() );
		$dispatcher->queue( owc_activity_log_siem_entry() );
		$dispatcher->flush();
	}
);

it(
	'continues sending after a non-2xx response',
	function () {
		owc_activity_log_siem_mock_wp();
		WP_Mock::userFunction( 'is_wp_error' )->andReturn( false );
		WP_Mock::userFunction( 'wp_remote_retrieve_response_code' )->andReturn( 500 );
		WP_Mock::userFunction( 'wp_safe_remote_post' )->twice()->andReturn( array() );

		$dispatcher = new SiemDispatcher( 'https://siem.example.com' );
		$dispatcher->queue( owc_activity_log_siem_entry() );
		$dispatcher->queue( owc_activity_log_siem_entry() );
		$dispatcher->flush();
	}
);

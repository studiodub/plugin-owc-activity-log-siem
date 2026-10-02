# OWC Activity Log

Tracks all WordPress activity such as posts, meta, options, users, taxonomy, comments, plugins, themes and more.

## Requirements

- PHP 8.1 or higher
- WordPress 6.7 or higher

## Installation

### Manual installation

1. Upload the 'owc-activity-log' folder in to the `/wp-content/plugins/` directory.
2. `cd /wp-content/plugins/owc-activity-log`
3. Run composer install, NPM asset build is in version control already.
4. Activate the plugin in via the WordPress admin.

### Composer installation

1. `composer source git@github.com:OpenWebconcept/plugin-owc-activity-log.git`
2. `composer require plugin/owc-activity-log`
3. `cd /wp-content/plugins/owc-activity-log`

## Hooks

### Admin overview page access

By default, the overview page inside the WordPress admin of this plugin is only accessible to administrators.

Some projects may require users with different roles or capabilities to access this page as well.  
This filter allows you to customize the required capability.

```php
add_filter('owc_activity_log_admin_page_overview_cap', function ($cap) {
    return 'superuser'; // Or any other capability.
});
```

## SIEM integration

Every logged event can be forwarded to a SIEM (or any HTTP log collector). Configure it under the plugin settings:

-   **SIEM endpoint URL** – HTTPS only. Leave empty to disable.
-   **SIEM API token** – optional, sent as `Authorization: Bearer <token>`. The token is never rendered back in the form.

Events are queued during the request and sent on `shutdown` (after the response has been flushed when running under PHP-FPM), one `POST` per event with a JSON body:

```json
{
    "site": "example.com",
    "event": "users_login",
    "user": "admin",
    "user_id": 1,
    "group": "users",
    "action": "login",
    "message": "User \"admin\" logged in.",
    "object_type": "user",
    "object_id": 1,
    "timestamp": "2026-10-01T12:00:00+00:00",
    "ip": "203.0.113.5",
    "meta": {}
}
```

`event` is `{group}_{action}`. `ip` is only included when IP logging is enabled, `meta` only when the event has context data.

Requests are made with `wp_safe_remote_post()` (TLS verification on, no redirects, 3s timeout). Endpoints that resolve to a private or loopback address are therefore blocked. To allow an internal SIEM host:

```php
add_filter('http_request_host_is_external', function ($external, $host) {
    return $external || 'siem.internal.example' === $host;
}, 10, 2);
```

### SIEM hooks

```php
// Modify (or flatten) the payload. Return an empty array to skip an event.
add_filter('owc_activity_log_siem_payload', function (array $payload, array $entry) {
    return array_merge($payload['meta'] ?? [], $payload);
}, 10, 2);

// Modify the HTTP request arguments (timeout, headers, ...).
add_filter('owc_activity_log_siem_request_args', function (array $args, array $payload) {
    $args['timeout'] = 5;
    return $args;
}, 10, 2);

// React to delivery failures (WP_Error or non-2xx response).
add_action('owc_activity_log_siem_request_failed', function ($response, array $payload) {
    // e.g. report to your monitoring.
}, 10, 2);

// Fires for every logged entry, regardless of SIEM configuration.
add_action('owc_activity_log_entry_logged', function (array $entry) {
    // ...
});
```

## Development

### Install dependencies

```bash
composer install
```

### Run tests

```bash
composer test
```

### Code style

```bash
composer phpcs
composer phpcbf
```

### Prefix vendor dependencies

```bash
composer prefix-dependencies
```

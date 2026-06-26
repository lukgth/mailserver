<?php
// Base URL behind nginx reverse proxy
$config['request_path'] = '/mail/';

// IMAP — STARTTLS on port 143 (internal Docker network)
$config['imap_host'] = 'tls://mailserver:143';

// SMTP — STARTTLS on port 587
$config['smtp_host'] = 'tls://mailserver:587';

// Accept self-signed certs on internal Docker network
$config['imap_conn_options'] = [
    'ssl' => [
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
    ],
];

$config['smtp_conn_options'] = [
    'ssl' => [
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
    ],
];

// Disable Roundcube's clickjacking check — nginx handles X-Frame-Options
$config['x_frame_options'] = false;

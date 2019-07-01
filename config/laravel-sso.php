<?php

return [
    /*
     |--------------------------------------------------------------------------
     | Laravel SSO Settings
     |--------------------------------------------------------------------------
     |
     | Set type of this web page. Possible options are: 'server' and 'broker'.
     |
     | You must specify either 'server' or 'broker'.
     |
     */

    'type' => 'broker',

    /*
     |--------------------------------------------------------------------------
     | Settings necessary for the SSO server & broker.
     |--------------------------------------------------------------------------
     |
     | These settings should be changed if this page is working as Both for SSO Server & broker
     |
     */

    'usersModel' => \App\User::class,
    'username'  =>  "email",
    /*
     |--------------------------------------------------------------------------
     | Settings necessary for the SSO server.
     |--------------------------------------------------------------------------
     |
     | These settings should be changed if this page is working as SSO server.
     |
     */


    'brokersModel' => Zefy\LaravelSSO\Models\Broker::class,

    // Table used in Zefy\LaravelSSO\Models\Broker model
    'brokersTable' => 'brokers',

    // Logged in user fields sent to brokers.
    'userFields' => [
        // Return array field name => database column name
        'id' => 'id',
        'email' => 'email',
    ],

    /*
     |--------------------------------------------------------------------------
     | Settings necessary for the SSO broker.
     |--------------------------------------------------------------------------
     |
     | These settings should be changed if this page is working as SSO broker.
     |
     */

    'serverUrl' => env('SSO_SERVER_URL', null),
    'serverUrlPublic'=> env('SSO_SERVER_URL_PUBLIC', null),
    'brokerName' => env('SSO_BROKER_NAME', null),
    'brokerSecret' => env('SSO_BROKER_SECRET', null),
];

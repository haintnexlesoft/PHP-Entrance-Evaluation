<?php

// Autoload files using the Composer autoloader.
require_once __DIR__ . '/../vendor/autoload.php';

use Admin\Ex03\Auth\Auth;

echo Auth::getRefreshToken();

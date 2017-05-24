<?php
require_once __DIR__ . '/common.php';

use CjsHttp\Cookie;

date_default_timezone_set("Asia/Shanghai");

$name = "c_userid";
$value = "123456";
$expire = time() + 86400;
$domain = "abc.com";
$path = "/";
$secure = false;
$httpOnly = true;
$cookieObj = new Cookie($name, $value, $expire, $path, $domain, $secure, $httpOnly);
echo $cookieObj; //c_userid=123456; expires=25-May-2017 10:34:20 GMT; path=/; domain=abc.com;httponly
echo PHP_EOL;

echo $cookieObj->__toString();

echo PHP_EOL;
setcookie($cookieObj->getName(),
            $cookieObj->getValue(),
            $cookieObj->getExpiresTime(),
            $cookieObj->getPath(),
            $cookieObj->getDomain(),
            $cookieObj->isSecure(),
            $cookieObj->isHttpOnly()
        );

<?php
require_once __DIR__ . '/common.php';

use CjsHttp\Request;

$request = Request::createFromGlobals();//返回Request类对象
echo $request->getBaseUrl() . PHP_EOL;
echo $request->getPathInfo() . PHP_EOL;
echo $request->getBasePath() . PHP_EOL;
echo PHP_EOL;




<?php
require_once __DIR__ . '/common.php';

use CjsHttp\Request;
$_GET['a1']= "a1val";
$_GET['b1']= "b1val";
$_POST['userid'] = '99999';
//$_SERVER['HTTP_HOST'] = "a.com";

$request = Request::createFromGlobals();//返回Request类对象
var_dump($request->isXmlHttpRequest() );
echo PHP_EOL;
echo "request method: ".$request->getMethod() . PHP_EOL;

echo "request schema: " . $request->getScheme() . PHP_EOL;
echo "a1=" . $request->query->get('a1') . PHP_EOL; //获取ulr?a1=参数值
echo "default val=" . $request->query->get('nono', "mo ren zhi") . PHP_EOL;  //获取get参数值

echo "post canshu userid=" . $request->request->get('userid', "8888") . PHP_EOL;//获取post参数值


echo "\$_SERVER['HTTP_HOST']=" . $request->server->get('HTTP_HOST', 'default.com') . PHP_EOL;
echo "\$_SERVER['SCRIPT_FILENAME']=" . $request->server->get('SCRIPT_FILENAME') . PHP_EOL;

echo "\$_COOKIE['PHPSESSID']=".$request->cookies->get('PHPSESSID');
echo $request->headers->get('host') . PHP_EOL; //获取请求头值

echo var_export($request->getLanguages() , true). PHP_EOL;

echo "request method: " . $request->getMethod() . PHP_EOL;
echo PHP_EOL;




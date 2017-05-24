<?php
/**
 * 响应内容示例
 */
require_once __DIR__ . '/common.php';

use CjsHttp\Response;
$response = new Response();
$response->setContent('<html><body><h1>Hello world!</h1></body></html>'); //设置响应内容
$response->setStatusCode(Response::HTTP_OK);//设置响应状态码
$response->headers->set('Content-Type', 'text/html');//设置响应头

//输出响应
$response->send();

<?php
/**
 * 响应内容示例
 */
require_once __DIR__ . '/common.php';

use CjsHttp\Response;
//设置响应内容-》设置响应状态码
$response = Response::create()->setContent('<html><body><h1>Hello world22222222!</h1></body></html>')->setStatusCode(Response::HTTP_OK);//设置响应状态码
$response->headers->set('Content-Type', 'text/html');//设置响应头

//输出响应
$response->send();

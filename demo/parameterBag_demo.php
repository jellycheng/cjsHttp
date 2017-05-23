<?php
require_once __DIR__ . '/common.php';

$data = [
        'userid'=>123456,
        'username'=>'cjs',
        'title'=>'标题哈哈',
        ];
$parameterBagObj = new \CjsHttp\Bag\ParameterBag($data);

echo $parameterBagObj->get('username') . PHP_EOL;
if(isWin()) {
    echo mb_convert_encoding("参数个数： " . count($parameterBagObj) . PHP_EOL, "GBK","UTF-8");
} else {
    echo "参数个数： " . count($parameterBagObj) . PHP_EOL;
}
var_dump($parameterBagObj->has('username'));
echo PHP_EOL;
$parameterBagObj->set('username2',"jelly");


foreach ($parameterBagObj as $k=>$v) {
    echo "key:" . $k . ", val:".$v . PHP_EOL;
}



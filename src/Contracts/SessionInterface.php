<?php
namespace CjsHttp\Contracts;

use CjsHttp\Bag\MetadataBag;

interface SessionInterface
{
    /**
     * 启动
     * @return bool True if session started.
     * @throws \RuntimeException If session fails to start.
     */
    public function start();

    /**
     * 获取session id
     */
    public function getId();

    /**
     * 设置 session ID
     * @param string $id
     *
     * @api
     */
    public function setId($id);

    /**
     * 获取session名
     */
    public function getName();

    /**
     * 设置session名
     */
    public function setName($name);
    //
    public function invalidate($lifetime = null);

    /**
     *
     */
    public function migrate($destroy = false, $lifetime = null);

    /**
     * Force the session to be saved and closed
     */
    public function save();

    public function has($name);

    public function get($name, $default = null);

    public function set($name, $value);

    public function all();

    public function replace(array $attributes);

    public function remove($name);

    public function clear();

    public function isStarted();

    public function registerBag(SessionBagInterface $bag);

    /**
     * @param string $name
     * @return SessionBagInterface
     */
    public function getBag($name);

    /**
     * Gets session meta.
     * @return MetadataBag
     */
    public function getMetadataBag();
}

<?php
namespace CjsHttp\Bag;

use CjsHttp\Contracts\SessionBagInterface;

class MetadataBag implements SessionBagInterface
{
    const CREATED = 'c';
    const UPDATED = 'u';
    const LIFETIME = 'l';

    /**
     * @var string
     */
    private $name = '__metadata';

    /**
     * @var string
     */
    private $storageKey;

    /**
     * @var array
     */
    protected $meta = array(self::CREATED => 0, self::UPDATED => 0, self::LIFETIME => 0);

    /**
     * Unix timestamp.
     *
     * @var int
     */
    private $lastUsed;

    /**
     * @var int
     */
    private $updateThreshold;


    public function __construct($storageKey = '_sf2_meta', $updateThreshold = 0)
    {
        $this->storageKey = $storageKey;
        $this->updateThreshold = $updateThreshold;
    }


    public function initialize(array &$array)
    {
        $this->meta = &$array;

        if (isset($array[self::CREATED])) {
            $this->lastUsed = $this->meta[self::UPDATED];

            $timeStamp = time();
            if ($timeStamp - $array[self::UPDATED] >= $this->updateThreshold) {
                $this->meta[self::UPDATED] = $timeStamp;
            }
        } else {
            $this->stampCreated();
        }
    }

    public function getLifetime()
    {
        return $this->meta[self::LIFETIME];
    }

    public function stampNew($lifetime = null)
    {
        $this->stampCreated($lifetime);
    }

    public function getStorageKey()
    {
        return $this->storageKey;
    }

    public function getCreated()
    {
        return $this->meta[self::CREATED];
    }


    public function getLastUsed()
    {
        return $this->lastUsed;
    }

    public function clear()
    {
        // nothing to do
    }

    public function getName()
    {
        return $this->name;
    }

    public function setName($name)
    {
        $this->name = $name;
    }

    private function stampCreated($lifetime = null)
    {
        $timeStamp = time();
        $this->meta[self::CREATED] = $this->meta[self::UPDATED] = $this->lastUsed = $timeStamp;
        $this->meta[self::LIFETIME] = (null === $lifetime) ? ini_get('session.cookie_lifetime') : $lifetime;
    }
}

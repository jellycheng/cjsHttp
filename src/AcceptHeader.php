<?php
namespace CjsHttp;

class AcceptHeader
{
    /**
     * @var AcceptHeaderItem[]
     */
    private $items = array();

    /**
     * @var bool
     */
    private $sorted = true;

    /**
     * @param AcceptHeaderItem[] $items
     */
    public function __construct(array $items)
    {
        foreach ($items as $item) {
            $this->add($item);
        }
    }

    /**
     * @param string $headerValue
     *
     * @return AcceptHeader
     */
    public static function fromString($headerValue)
    {
        $index = 0;

        return new self(array_map(function ($itemValue) use (&$index) {
            $item = AcceptHeaderItem::fromString($itemValue);
            $item->setIndex($index++);

            return $item;
        }, preg_split('/\s*(?:,*("[^"]+"),*|,*(\'[^\']+\'),*|,+)\s*/', $headerValue, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE)));
    }

    public function __toString()
    {
        return implode(',', $this->items);
    }

    public function has($value)
    {
        return isset($this->items[$value]);
    }

    /**
     * @param string $value
     *
     * @return AcceptHeaderItem|null
     */
    public function get($value)
    {
        return isset($this->items[$value]) ? $this->items[$value] : null;
    }

    /**
     * @param AcceptHeaderItem $item
     *
     * @return AcceptHeader
     */
    public function add(AcceptHeaderItem $item)
    {
        $this->items[$item->getValue()] = $item;
        $this->sorted = false;

        return $this;
    }

    /**
     * @return AcceptHeaderItem[]
     */
    public function all()
    {
        $this->sort();
        return $this->items;
    }

    public function filter($pattern)
    {
        return new self(array_filter($this->items, function (AcceptHeaderItem $item) use ($pattern) {
            return preg_match($pattern, $item->getValue());
        }));
    }

    /**
     * @return AcceptHeaderItem|null
     */
    public function first()
    {
        $this->sort();
        return !empty($this->items) ? reset($this->items) : null;
    }

    private function sort()
    {
        if (!$this->sorted) {
            uasort($this->items, function ($a, $b) {
                $qA = $a->getQuality();
                $qB = $b->getQuality();

                if ($qA === $qB) {
                    return $a->getIndex() > $b->getIndex() ? 1 : -1;
                }

                return $qA > $qB ? -1 : 1;
            });

            $this->sorted = true;
        }
    }
}

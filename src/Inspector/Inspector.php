<?php

namespace Typomedia\Inspector;

use Exception;
use Typomedia\Inspector\Exception\RuntimeException;

class Inspector
{
    /**
     * @var string
     */
    public const VERSION = '1.3.1';

    /**
     * @var Crawler
     */
    private Crawler $crawler;

    public function __construct()
    {
        $this->crawler = new Crawler();
    }

    /**
     * @param string $lockfile
     * @param string $whitelist
     * @return array
     * @throws Exception
     */
    public function check(string $lockfile, string $whitelist): array
    {
        if (!file_exists($lockfile)) {
            throw new RuntimeException(sprintf('The lock file "%s" does not exist.', $lockfile));
        }

        if (!file_exists($whitelist)) {
            throw new RuntimeException(sprintf('The whitelist file "%s" does not exist.', $whitelist));
        }

        return $this->crawler->parse($lockfile, $whitelist);
    }
}

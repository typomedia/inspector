<?php

namespace Typomedia\Inspector\Tests;

use PHPUnit\Framework\TestCase;
use Typomedia\Inspector\Crawler;

class CrawlerTest extends TestCase
{
    public function testGetLock()
    {
        $crawler = new Crawler();
        $expected = $crawler->getLockContents2('composer.lock');
        $actual = $crawler->getContents('composer.lock');
        $this->assertEquals($expected, $actual);
    }
}

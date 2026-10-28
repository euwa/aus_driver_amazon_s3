<?php

/***
 *
 * This file is part of an extension for TYPO3 CMS.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 ***/

declare(strict_types=1);

namespace AUS\AusDriverAmazonS3\EventListener;

use AUS\AusDriverAmazonS3\Driver\AmazonS3Driver;
use TYPO3\CMS\Core\Resource\StorageRepository;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\Directive;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\Event\PolicyMutatedEvent;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\UriValue;

/**
 * Allows images and media of all Amazon S3 storages (bucket domain or publicBaseUrl) in the Content-Security-Policy
 *
 * @package AUS\AusDriverAmazonS3\EventListener
 */
class PolicyMutatedEventListener
{
    public function __construct(private readonly StorageRepository $storageRepository)
    {
    }

    public function __invoke(PolicyMutatedEvent $event): void
    {
        $sources = [];
        foreach ($this->storageRepository->findByStorageType(AmazonS3Driver::DRIVER_TYPE) as $storage) {
            $publicUrl = $storage->getPublicUrl($storage->getRootLevelFolder(false));
            $host = parse_url((string)$publicUrl, PHP_URL_HOST);
            if (!is_string($host) || $host === '') {
                continue;
            }
            $scheme = parse_url((string)$publicUrl, PHP_URL_SCHEME);
            $port = parse_url((string)$publicUrl, PHP_URL_PORT);
            $source = (is_string($scheme) ? $scheme . '://' : '') . $host . (is_int($port) ? ':' . $port : '');
            $sources[$source] = new UriValue($source);
        }

        if ($sources === []) {
            return;
        }

        $policy = $event->getCurrentPolicy()
            ->extend(Directive::ImgSrc, ...array_values($sources))
            ->extend(Directive::MediaSrc, ...array_values($sources));
        $event->setCurrentPolicy($policy);
    }
}

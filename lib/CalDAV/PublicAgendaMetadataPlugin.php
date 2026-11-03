<?php

namespace ESN\CalDAV;

use ESN\CalDAV\Schedule\CalendarObjectHelper;
use ESN\DAV\VObjectCachePlugin;
use ESN\Utils\AuthTenant;
use ESN\Utils\TenantType;
use Sabre\CalDAV\ICalendarObject;
use Sabre\DAV\Exception\Forbidden;
use Sabre\DAV\Exception\NotFound;
use Sabre\DAV\Server;
use Sabre\DAV\ServerPlugin;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\ResponseInterface;
use Sabre\VObject\Component\VCalendar;

/**
 * CalDAV clients may round-trip booking metadata, but cannot author it. Restore
 * stored values before scheduling, including when a client drops X-properties.
 */
class PublicAgendaMetadataPlugin extends ServerPlugin {
    protected $server;
    private bool $serverWrite = false;

    function initialize(Server $server) {
        $this->server = $server;
        $server->on('beforeMethod:*', [$this, 'resetAuthentication'], 1);
        $server->on('auth:success', [$this, 'authenticated']);
        $server->on('calendarObjectChange', [$this, 'calendarObjectChange'], Plugin::PRIORITY_BEFORE_SCHEDULING - 20);
        // COPY/MOVE bypass calendarObjectChange and otherwise replace stored metadata verbatim.
        $server->on('beforeCopy', [$this, 'beforeCopy'], 40);
        $server->on('beforeMove', [$this, 'beforeMove'], 40);
    }

    function getPluginName() {
        return 'caldav-public-agenda-metadata';
    }

    function resetAuthentication() {
        $this->serverWrite = false;
    }

    function authenticated(AuthTenant $tenant, bool $adminImpersonation = false) {
        // Booking and cancellation currently use verified admin impersonation;
        // technical tokens are also trusted. Neither a header nor an HTTP method is proof.
        $this->serverWrite = $adminImpersonation || $tenant->tenantType === TenantType::Technical;
    }

    function calendarObjectChange(RequestInterface $request, ResponseInterface $response, VCalendar $vCal, $calendarPath, &$modified, $isNew) {
        if ($this->serverWrite) return;

        $oldCalendar = $isNew ? null : $this->calendarAt($request->getPath());
        if ($this->filterCalendar($vCal, $oldCalendar)) {
            $modified = true;
        }
    }

    // Explicit client iTIP submissions bypass calendarObjectChange. Scheduling
    // supplies the previous object so they obey the same policy as PUT.
    function filterCalendar(VCalendar $vCal, ?VCalendar $oldCalendar): bool {
        if ($this->serverWrite) return false;

        $modified = false;
        $oldEvents = $oldCalendar ? CalendarObjectHelper::indexEventsByRecurrenceKey($oldCalendar) : [];

        foreach ($vCal->select('VEVENT') as $event) {
            $key = CalendarObjectHelper::recurrenceKey($event);
            // New overrides inherit the server's series metadata, never the client's values.
            $storedEvent = $oldEvents[$key] ?? $oldEvents[CalendarObjectHelper::MASTER_EVENT] ?? null;
            foreach (VObjectPropertyRegistry::PUBLIC_AGENDA_METADATA_PROPERTIES as $name) {
                $stored = $storedEvent ? $storedEvent->select($name) : [];
                $incoming = $event->select($name);
                if (array_map(fn($p) => $p->serialize(), array_values($stored)) ===
                    array_map(fn($p) => $p->serialize(), array_values($incoming))) {
                    continue;
                }
                unset($event->$name);
                foreach ($stored as $property) {
                    $event->add(clone $property);
                }
                $modified = true;
            }
        }
        return $modified;
    }

    function beforeCopy($sourcePath, $destinationPath) {
        if ($this->serverWrite) return;

        if ($this->hasMetadata($this->calendarAt($sourcePath)) || $this->hasMetadata($this->calendarAt($destinationPath))) {
            throw new Forbidden('Public agenda metadata cannot be copied or overwritten by a client.');
        }
    }

    function beforeMove($sourcePath, $destinationPath) {
        if ($this->serverWrite) return;

        // A rename keeps server-authored metadata. Overwriting a booking would erase it.
        if ($this->hasMetadata($this->calendarAt($destinationPath))) {
            throw new Forbidden('Public agenda metadata cannot be overwritten by a client.');
        }
    }

    private function calendarAt(string $path): ?VCalendar {
        try {
            $node = $this->server->tree->getNodeForPath($path);
        } catch (NotFound $e) {
            return null;
        }
        return $node instanceof ICalendarObject ? VObjectCachePlugin::cacheFor($this->server)->read($node->get()) : null;
    }

    private function hasMetadata(?VCalendar $calendar): bool {
        if (!$calendar) return false;

        foreach ($calendar->select('VEVENT') as $event) {
            foreach (VObjectPropertyRegistry::PUBLIC_AGENDA_METADATA_PROPERTIES as $name) {
                if ($event->select($name)) return true;
            }
        }
        return false;
    }
}

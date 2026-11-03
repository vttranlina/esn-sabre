<?php

namespace ESN\CalDAV;

use ESN\Utils\AuthTenant;
use ESN\Utils\TenantType;
use PHPUnit\Framework\Attributes\DataProvider;
use Sabre\CalDAV\ICalendarObject;
use Sabre\DAV\Exception\Forbidden;
use Sabre\DAV\Server;
use Sabre\HTTP\Request;
use Sabre\HTTP\Response;
use Sabre\VObject\Reader;

class PublicAgendaMetadataPluginTest extends \PHPUnit\Framework\TestCase {
    private Server $server;

    function setUp(): void {
        VObjectPropertyRegistry::register();
        $this->server = new Server([]);
        $this->server->addPlugin(new PublicAgendaMetadataPlugin());
    }

    static function metadata() {
        return [
            ['X-PUBLICLY-CREATED', 'TRUE', 'FALSE'],
            ['X-PUBLICLY-CREATOR', 'booker@example.com', 'attacker@example.com'],
            ['X-PUBLICLY-DELETED', 'TRUE', 'FALSE'],
            ['X-PUBLICLY-CANCELLED-BY', 'booker@example.com', 'attacker@example.com'],
            ['X-OPENPAAS-BOOKING-LINK', 'server-link', 'client-link']
        ];
    }

    #[DataProvider('metadata')]
    function testClientCannotAddMetadataOnCreationOrUpdate($name, $stored, $forged) {
        $this->store('event.ics', $this->calendar(''));
        foreach ([true, false] as $isNew) {
            $calendar = Reader::read($this->calendar("$name:$forged"));
            $this->assertTrue($this->change($calendar, $isNew));
            $this->assertCount(0, $calendar->VEVENT->select($name));
        }
    }

    #[DataProvider('metadata')]
    function testClientCannotModifyOrRemoveStoredMetadata($name, $stored, $forged) {
        $this->store('event.ics', $this->calendar("$name:$stored"));
        foreach (["$name:$forged", ''] as $incoming) {
            $calendar = Reader::read($this->calendar($incoming));
            $calendar->VEVENT->SUMMARY = 'Client edit';
            $this->assertTrue($this->change($calendar));
            $expected = Reader::read($this->calendar("$name:$stored"));
            $this->assertSame($expected->VEVENT->$name->serialize(), $calendar->VEVENT->$name->serialize());
            $this->assertSame('Client edit', (string) $calendar->VEVENT->SUMMARY);
        }
    }

    function testRestoresParametersAndRemovesDuplicatePropertiesBeforeScheduling() {
        $property = 'X-PUBLICLY-CREATOR;LANGUAGE=en:booker@example.com';
        $this->store('event.ics', $this->calendar($property));
        $calendar = Reader::read($this->calendar("X-PUBLICLY-CREATOR:attacker@example.com\r\nX-PUBLICLY-CREATOR:other@example.com"));
        $observed = null;
        $this->server->on('calendarObjectChange', function($request, $response, $calendar) use (&$observed) {
            $observed = $calendar->VEVENT->{'X-PUBLICLY-CREATOR'}->serialize();
        }, Plugin::PRIORITY_BEFORE_SCHEDULING);

        $this->assertTrue($this->change($calendar));

        $this->assertSame($property . "\r\n", $observed);
        $this->assertCount(1, $calendar->VEVENT->select('X-PUBLICLY-CREATOR'));
    }

    function testUnchangedMetadataDoesNotFlagAModification() {
        $this->store('event.ics', $this->calendar('X-PUBLICLY-CREATED:TRUE'));
        $calendar = Reader::read($this->calendar('X-PUBLICLY-CREATED:TRUE'));
        $this->assertFalse($this->change($calendar));
    }

    function testProtectsRecurrenceMetadataAndInheritsSeriesMetadataForNewOverrides() {
        $old = Reader::read($this->calendar('X-PUBLICLY-CREATOR:series@example.com'));
        $old->VEVENT->RRULE = 'FREQ=DAILY;COUNT=3';
        $override = clone $old->VEVENT;
        $override->{'RECURRENCE-ID'} = '20261104T090000Z';
        $override->{'X-PUBLICLY-CREATOR'} = 'override@example.com';
        unset($override->RRULE);
        $old->add($override);
        $this->store('event.ics', $old->serialize());
        $calendar = clone $old;
        foreach ($calendar->select('VEVENT') as $event) unset($event->{'X-PUBLICLY-CREATOR'});
        $newOverride = clone $override;
        $newOverride->{'RECURRENCE-ID'} = '20261105T090000Z';
        $newOverride->{'X-PUBLICLY-CREATOR'} = 'attacker@example.com';
        $calendar->add($newOverride);

        $this->assertTrue($this->change($calendar));

        $events = array_values($calendar->select('VEVENT'));
        $this->assertSame('series@example.com', (string) $events[0]->{'X-PUBLICLY-CREATOR'});
        $this->assertSame('override@example.com', (string) $events[1]->{'X-PUBLICLY-CREATOR'});
        $this->assertSame('series@example.com', (string) $events[2]->{'X-PUBLICLY-CREATOR'});
        $this->assertSame('override@example.com', (string) array_values($old->select('VEVENT'))[1]->{'X-PUBLICLY-CREATOR'});
    }

    function testTechnicalAndAdminImpersonatedWritesCanCreateUpdateAndRemoveMetadata() {
        $this->store('event.ics', $this->calendar('X-PUBLICLY-CREATOR:old@example.com'));
        foreach ([[TenantType::Technical, false], [TenantType::User, true]] as [$type, $admin]) {
            $this->server->emit('auth:success', [new AuthTenant('user', 'domain', $type), $admin]);
            foreach ([true, false] as $isNew) {
                $calendar = Reader::read($this->calendar('X-PUBLICLY-CREATOR:new@example.com'));
                $this->assertFalse($this->change($calendar, $isNew));
                $this->assertSame('new@example.com', (string) $calendar->VEVENT->{'X-PUBLICLY-CREATOR'});
            }
            $calendar = Reader::read($this->calendar(''));
            $this->assertFalse($this->change($calendar));
            $this->assertCount(0, $calendar->VEVENT->select('X-PUBLICLY-CREATOR'));
        }
    }

    function testUserAuthenticationAndNewRequestResetServerPrivileges() {
        $tenant = new AuthTenant('user', 'domain', TenantType::Technical);
        foreach (['auth:success', 'beforeMethod:PUT'] as $resetEvent) {
            $this->server->emit('auth:success', [$tenant]);
            $args = $resetEvent === 'auth:success' ? [new AuthTenant('user', 'domain')] : [];
            $this->server->emit($resetEvent, $args);
            $calendar = Reader::read($this->calendar('X-PUBLICLY-CREATED:TRUE'));
            $this->assertTrue($this->change($calendar, true, 'ITIP'));
            $this->assertCount(0, $calendar->VEVENT->select('X-PUBLICLY-CREATED'));
        }
    }

    function testClientCannotCopyBookingMetadata() {
        $this->store('event.ics', $this->calendar('X-PUBLICLY-CREATED:TRUE'));
        $this->expectException(Forbidden::class);
        $this->server->emit('beforeCopy', ['event.ics', 'copy.ics']);
    }

    #[DataProvider('overwriteMethods')]
    function testClientCannotOverwriteBookingWithCopyOrMove($event) {
        $this->store('event.ics', $this->calendar(''));
        $this->store('booking.ics', $this->calendar('X-PUBLICLY-CREATED:TRUE'));
        $this->expectException(Forbidden::class);
        $this->server->emit($event, ['event.ics', 'booking.ics']);
    }

    static function overwriteMethods() {
        return [['beforeCopy'], ['beforeMove']];
    }

    function testClientCanRenameBookingAndCopyOrdinaryEvents() {
        $this->store('booking.ics', $this->calendar('X-PUBLICLY-CREATED:TRUE'));
        $this->store('event.ics', $this->calendar(''));
        $this->assertTrue($this->server->emit('beforeMove', ['booking.ics', 'renamed.ics']));
        $this->assertTrue($this->server->emit('beforeCopy', ['event.ics', 'copy.ics']));
    }

    private function store(string $name, string $data) {
        $node = $this->createStub(ICalendarObject::class);
        $node->method('getName')->willReturn($name);
        $node->method('get')->willReturn($data);
        $this->server->tree->getNodeForPath('')->addChild($node);
    }

    private function change($calendar, bool $isNew = false, string $method = 'PUT'): bool {
        $modified = false;
        $this->server->emit('calendarObjectChange', [new Request($method, '/event.ics'), new Response(), $calendar, '', &$modified, $isNew]);
        return $modified;
    }

    private function calendar(string $metadata): string {
        return implode("\r\n", ['BEGIN:VCALENDAR', 'VERSION:2.0', 'BEGIN:VEVENT', 'UID:booking',
            'DTSTART:20261103T090000Z', 'SUMMARY:Booking', $metadata, 'END:VEVENT', 'END:VCALENDAR', '']);
    }
}

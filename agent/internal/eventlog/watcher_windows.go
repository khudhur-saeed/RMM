//go:build windows

package eventlog

import (
	"encoding/xml"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWevtapi = windows.NewLazySystemDLL("wevtapi.dll")

	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXml        = 1
	errorInsufficientBuffer  = 122
	errorNoMoreItems         = 259
)

// Raw XML structures for Windows Event schema
type xmlEventDataEntry struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type xmlEvent struct {
	System struct {
		EventID     int    `xml:"EventID"`
		Channel     string `xml:"Channel"`
		Computer    string `xml:"Computer"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []xmlEventDataEntry `xml:"Data"`
	} `xml:"EventData"`
}

// Watcher manages native Windows Event Log queries with deduplication.
type Watcher struct {
	mu        sync.Mutex
	seenEvents map[string]struct{}
}

// NewWatcher initializes a new Windows Event Log watcher with deduplication cache.
func NewWatcher() *Watcher {
	return &Watcher{
		seenEvents: make(map[string]struct{}),
	}
}

// ReadSecurityEvents queries critical Security (4624, 4625) and System (7045) events,
// filtering out previously ingested records to prevent continuous event replay.
func (w *Watcher) ReadSecurityEvents(maxEvents uint32) ([]SecurityEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	var collected []SecurityEvent

	// 1. Query Security Channel: Logon (4624) and Failed Logon (4625)
	secQuery := "*[System[(EventID=4624 or EventID=4625)]]"
	secEvents, err := queryChannelEvents("Security", secQuery, maxEvents)
	if err == nil {
		for _, ev := range secEvents {
			key := fmt.Sprintf("%s:%d:%s:%s", ev.Channel, ev.EventID, ev.TimeCreated, ev.TargetUserName)
			if _, seen := w.seenEvents[key]; !seen {
				w.seenEvents[key] = struct{}{}
				collected = append(collected, ev)
			}
		}
	}

	// 2. Query System Channel: Service Creation (7045)
	sysQuery := "*[System[(EventID=7045)]]"
	sysEvents, err := queryChannelEvents("System", sysQuery, maxEvents)
	if err == nil {
		for _, ev := range sysEvents {
			key := fmt.Sprintf("%s:%d:%s:%s", ev.Channel, ev.EventID, ev.TimeCreated, ev.ServiceName)
			if _, seen := w.seenEvents[key]; !seen {
				w.seenEvents[key] = struct{}{}
				collected = append(collected, ev)
			}
		}
	}

	// Bound deduplication cache to prevent memory creep
	if len(w.seenEvents) > 10000 {
		w.seenEvents = make(map[string]struct{})
		for _, ev := range collected {
			key := fmt.Sprintf("%s:%d:%s:%s", ev.Channel, ev.EventID, ev.TimeCreated, ev.TargetUserName)
			w.seenEvents[key] = struct{}{}
		}
	}

	return collected, nil
}

// queryChannelEvents opens channel handles and retrieves rendered event payloads.
func queryChannelEvents(channel, xpath string, maxCount uint32) ([]SecurityEvent, error) {
	chanUTF16, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, err
	}

	queryUTF16, err := windows.UTF16PtrFromString(xpath)
	if err != nil {
		return nil, err
	}

	flags := uint32(evtQueryChannelPath | evtQueryReverseDirection)
	hQuery, _, qErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(chanUTF16)),
		uintptr(unsafe.Pointer(queryUTF16)),
		uintptr(flags),
	)
	if hQuery == 0 {
		return nil, fmt.Errorf("EvtQuery failed on %s: %w", channel, qErr)
	}
	defer procEvtClose.Call(hQuery)

	eventHandles := make([]windows.Handle, maxCount)
	var returned uint32

	r1, _, _ := procEvtNext.Call(
		hQuery,
		uintptr(maxCount),
		uintptr(unsafe.Pointer(&eventHandles[0])),
		0, // Infinite wait
		0,
		uintptr(unsafe.Pointer(&returned)),
	)
	if r1 == 0 && returned == 0 {
		return []SecurityEvent{}, nil
	}

	var parsedEvents []SecurityEvent
	for i := uint32(0); i < returned; i++ {
		hEvt := eventHandles[i]
		xmlContent, err := renderEventXML(hEvt)
		procEvtClose.Call(uintptr(hEvt))

		if err != nil {
			continue
		}

		secEvt, err := parseEventXML(xmlContent)
		if err == nil {
			parsedEvents = append(parsedEvents, secEvt)
		}
	}

	return parsedEvents, nil
}

// renderEventXML retrieves the full XML representation using the two-pass buffer pattern.
func renderEventXML(hEvt windows.Handle) (string, error) {
	var bufferUsed, propertyCount uint32

	// Pass 1: Query required buffer size
	r1, _, _ := procEvtRender.Call(
		0,
		uintptr(hEvt),
		uintptr(evtRenderEventXml),
		0,
		0,
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)

	if r1 == 0 && bufferUsed == 0 {
		return "", fmt.Errorf("failed to determine EvtRender buffer size")
	}

	// Pass 2: Allocate UTF-16 buffer and populate data
	buf := make([]uint16, bufferUsed/2)
	r1, _, err := procEvtRender.Call(
		0,
		uintptr(hEvt),
		uintptr(evtRenderEventXml),
		uintptr(bufferUsed),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("EvtRender failed: %w", err)
	}

	return syscall.UTF16ToString(buf), nil
}

// parseEventXML extracts structured telemetry from the raw event XML document.
func parseEventXML(xmlData string) (SecurityEvent, error) {
	var ev xmlEvent
	if err := xml.Unmarshal([]byte(xmlData), &ev); err != nil {
		return SecurityEvent{}, err
	}

	event := SecurityEvent{
		EventID:      ev.System.EventID,
		Channel:      ev.System.Channel,
		TimeCreated:  ev.System.TimeCreated.SystemTime,
		ComputerName: ev.System.Computer,
	}

	dataMap := make(map[string]string)
	for _, entry := range ev.EventData.Data {
		dataMap[entry.Name] = entry.Value
	}

	switch event.EventID {
	case 4624, 4625:
		event.TargetUserName = dataMap["TargetUserName"]
		event.TargetDomainName = dataMap["TargetDomainName"]
		event.IpAddress = dataMap["IpAddress"]
		if val, ok := dataMap["LogonType"]; ok {
			var lt int
			fmt.Sscanf(val, "%d", &lt)
			event.LogonType = lt
		}
		if event.EventID == 4625 {
			event.FailureReason = dataMap["Status"]
			if event.FailureReason == "" {
				event.FailureReason = dataMap["SubStatus"]
			}
		}
	case 7045:
		event.ServiceName = dataMap["ServiceName"]
		event.ImagePath = dataMap["ImagePath"]
	}

	return event, nil
}
